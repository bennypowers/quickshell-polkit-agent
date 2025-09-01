/*
 * quickshell-polkit-agent
 * Copyright (C) 2025 Benny Powers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ipc-server.h"
#include "polkit-wrapper.h"
#include "message-validator.h"
#include "security.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include "logging.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTimer>
#include <QDateTime>
#include <unistd.h>

IPCServer::IPCServer(PolkitWrapper *polkitWrapper, QObject *parent)
    : QObject(parent)
    , m_server(new QLocalServer(this))
    , m_currentClient(nullptr)
    , m_polkitWrapper(polkitWrapper)
    , m_rateLimitTimer(new QTimer(this))
    , m_heartbeatTimer(new QTimer(this))
    , m_lastHeartbeat(0)
    , m_clientConnectionVersion(0)
    , m_sessionStartTime(0)
    , m_sessionTimeoutTimer(new QTimer(this))
{
    // Connect polkit wrapper signals
    connect(m_polkitWrapper, &PolkitWrapper::showAuthDialog,
            this, &IPCServer::onShowAuthDialog);
    connect(m_polkitWrapper, &PolkitWrapper::authorizationResult,
            this, &IPCServer::onAuthorizationResult);
    connect(m_polkitWrapper, &PolkitWrapper::authorizationError,
            this, &IPCServer::onAuthorizationError);
    connect(m_polkitWrapper, &PolkitWrapper::showPasswordRequest,
            this, &IPCServer::onShowPasswordRequest);
    
    // Connect server signals
    connect(m_server, &QLocalServer::newConnection,
            this, &IPCServer::onNewConnection);
    
    // Setup heartbeat timer
    connect(m_heartbeatTimer, &QTimer::timeout,
            this, &IPCServer::onHeartbeatTimeout);
    m_heartbeatTimer->setSingleShot(false);
    m_heartbeatTimer->setInterval(HEARTBEAT_INTERVAL_MS);
    
    // Setup session timeout timer
    connect(m_sessionTimeoutTimer, &QTimer::timeout,
            this, &IPCServer::onSessionTimeout);
    m_sessionTimeoutTimer->setSingleShot(false);
    m_sessionTimeoutTimer->setInterval(SecurityManager::SESSION_TIMEOUT_MS);
}

IPCServer::~IPCServer()
{
    if (m_server->isListening()) {
        m_server->close();
    }
}

bool IPCServer::startServer()
{
    // Check for custom socket path in environment (for testing)
    QString customSocketPath = qEnvironmentVariable("QUICKSHELL_POLKIT_SOCKET");
    QString fullSocketPath;
    
    if (!customSocketPath.isEmpty()) {
        // Use custom socket path for testing
        fullSocketPath = customSocketPath;
        qCDebug(ipcServer) << "Using custom socket path from environment:" << fullSocketPath;
    } else {
        // Check if systemd provided RUNTIME_DIRECTORY (when run as service)
        QString runtimeDirectory = qEnvironmentVariable("RUNTIME_DIRECTORY");
        if (!runtimeDirectory.isEmpty()) {
            // systemd provides absolute path to our runtime directory
            fullSocketPath = QString("%1/quickshell-polkit").arg(runtimeDirectory);
            qCDebug(ipcServer) << "Using RUNTIME_DIRECTORY:" << runtimeDirectory << "-> full path:" << fullSocketPath;
        } else {
            // Fallback: create socket in user runtime directory
            QString runtimeDir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
            if (!runtimeDir.isEmpty()) {
                fullSocketPath = QString("%1/quickshell-polkit/quickshell-polkit").arg(runtimeDir);
                
                // Ensure parent directory exists (only create if it doesn't exist)
                QFileInfo socketInfo(fullSocketPath);
                QString parentPath = socketInfo.absolutePath();
                if (!QDir(parentPath).exists()) {
                    QDir().mkpath(parentPath);
                }
            } else {
                fullSocketPath = QString("/tmp/quickshell-polkit-%1/quickshell-polkit").arg(getuid());
                
                // Ensure parent directory exists
                QFileInfo socketInfo(fullSocketPath);
                QDir().mkpath(socketInfo.absolutePath());
            }
        }
    }
    
    // Remove existing socket if it exists
    QFile::remove(fullSocketPath);
    
    if (!m_server->listen(fullSocketPath)) {
        qCritical() << "Failed to start IPC server:" << m_server->errorString();
        return false;
    }
    
    qCDebug(ipcServer) << "IPC server listening on:" << fullSocketPath;
    return true;
}

void IPCServer::onNewConnection()
{
    if (m_currentClient) {
        // Only allow one client for now
        auto newClient = m_server->nextPendingConnection();
        qCDebug(ipcServer) << "Rejecting additional client connection";
        newClient->close();
        newClient->deleteLater();
        return;
    }
    
    m_currentClient = m_server->nextPendingConnection();
    
    connect(m_currentClient, &QLocalSocket::disconnected,
            this, &IPCServer::onClientDisconnected);
    connect(m_currentClient, &QLocalSocket::readyRead,
            this, &IPCServer::onClientDataReady);
    connect(m_currentClient, QOverload<QLocalSocket::LocalSocketError>::of(&QLocalSocket::errorOccurred),
            [this](QLocalSocket::LocalSocketError error) {
                qCDebug(ipcServer) << "Client socket error:" << error;
            });
    
    qCDebug(ipcServer) << "Quickshell client connected, state:" << m_currentClient->state();
    
    // Increment connection version to detect client restarts
    m_clientConnectionVersion++;
    m_lastHeartbeat = QDateTime::currentMSecsSinceEpoch();
    m_sessionStartTime = SecurityManager::getCurrentTimestamp();
    
    // Start heartbeat and session monitoring
    startHeartbeat();
    m_sessionTimeoutTimer->start();
    
    SecurityManager::auditLog("CLIENT_CONNECTED", QString("version=%1").arg(m_clientConnectionVersion), "SUCCESS");
    
    // Send welcome message with connection version
    QJsonObject welcome;
    welcome["type"] = "welcome";
    welcome["message"] = "Connected to quickshell-polkit-agent";
    welcome["connection_version"] = m_clientConnectionVersion;
    sendMessageToClient(welcome);
    
    // Replay any queued messages
    replayQueuedMessages();
}

void IPCServer::onClientDisconnected()
{
    if (m_currentClient) {
        qCDebug(ipcServer) << "Quickshell client disconnected, error:" << m_currentClient->errorString();
        m_currentClient->deleteLater();
        m_currentClient = nullptr;
        
        // Stop heartbeat and session monitoring
        stopHeartbeat();
        m_sessionTimeoutTimer->stop();
        
        SecurityManager::auditLog("CLIENT_DISCONNECTED", "Session ended", "SUCCESS");
        qCDebug(ipcServer) << "Client connection cleaned up, ready for reconnection";
    }
}

void IPCServer::onClientDataReady()
{
    if (!m_currentClient) return;
    
    QByteArray data = m_currentClient->readAll();
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);
    
    if (error.error != QJsonParseError::NoError) {
        qCWarning(ipcServer) << "Invalid JSON from client:" << error.errorString();
        return;
    }
    
    handleClientMessage(doc.object());
}

void IPCServer::handleClientMessage(const QJsonObject &message)
{
    // Check rate limiting first
    if (!checkRateLimit()) {
        qCWarning(ipcServer) << "Rate limit exceeded, dropping message";
        sendErrorToClient("Rate limit exceeded");
        SecurityManager::auditLog("RATE_LIMIT", "Client exceeded message rate limit", "BLOCKED");
        return;
    }
    
    // Check session timeout
    if (SecurityManager::isSessionExpired(m_sessionStartTime)) {
        qCWarning(ipcServer) << "Session expired, disconnecting client";
        SecurityManager::auditLog("SESSION_EXPIRED", "Client session timed out", "DISCONNECTED");
        if (m_currentClient) {
            m_currentClient->disconnectFromServer();
        }
        return;
    }
    
    // Validate message before processing
    ValidationResult validation = MessageValidator::validateMessage(message);
    if (!validation.valid) {
        qCWarning(ipcServer) << "Invalid message from client:" << validation.error;
        sendErrorToClient("Invalid message: " + validation.error);
        SecurityManager::auditLog("MESSAGE_VALIDATION", validation.error, "REJECTED");
        return;
    }
    
    // Optional HMAC verification (for future enhanced security)
    if (message.contains("hmac")) {
        if (!SecurityManager::verifyMessage(message)) {
            qCWarning(ipcServer) << "HMAC verification failed";
            sendErrorToClient("Message authentication failed");
            return;
        }
        qCDebug(ipcServer) << "Message HMAC verified successfully";
    }
    
    QString type = message["type"].toString();
    qCDebug(ipcServer) << "Received valid client message type:" << type;
    
    if (type == "check_authorization") {
        QString actionId = message["action_id"].toString();
        QString details = message["details"].toString();
        
        qCDebug(ipcServer) << "Client requesting authorization for:" << actionId;
        SecurityManager::auditLog("AUTH_REQUEST", QString("action=%1").arg(actionId), "PROCESSING");
        
        // Reset session timeout on legitimate auth activity
        resetSessionTimeout();
        
        m_polkitWrapper->checkAuthorization(actionId, details);
        
    } else if (type == "cancel_authorization") {
        qCDebug(ipcServer) << "Client cancelling authorization";
        SecurityManager::auditLog("AUTH_CANCEL", "Client cancelled authentication", "CANCELLED");
        m_polkitWrapper->cancelAuthorization();
        
    } else if (type == "submit_authentication") {
        QString cookie = message["cookie"].toString();
        QString response = message["response"].toString();
        
        qCDebug(ipcServer) << "Client submitting authentication, response length:" << response.length();
        qCDebug(polkitSensitive) << "Auth submission for cookie:" << cookie;
        SecurityManager::auditLog("AUTH_SUBMIT", QString("response_length=%1").arg(response.length()), "SUBMITTED");
        
        // Reset session timeout on auth submission activity
        resetSessionTimeout();
        
        m_polkitWrapper->submitAuthenticationResponse(cookie, response);
        
    } else if (type == "heartbeat") {
        // Update last heartbeat timestamp
        m_lastHeartbeat = QDateTime::currentMSecsSinceEpoch();
        qCDebug(ipcServer) << "Received heartbeat from client";
        
        // Reset session timeout on heartbeat (shows client is active)
        resetSessionTimeout();
        
        // Send heartbeat response
        QJsonObject heartbeatResponse;
        heartbeatResponse["type"] = "heartbeat_ack";
        heartbeatResponse["timestamp"] = m_lastHeartbeat;
        sendMessageToClient(heartbeatResponse);
        
    } else {
        // This should never happen due to validation, but keep as safety net
        qCWarning(ipcServer) << "Unknown message type from client:" << type;
        sendErrorToClient("Unknown message type: " + type);
    }
}

void IPCServer::sendMessageToClient(const QJsonObject &message)
{
    qCDebug(ipcServer) << "sendMessageToClient called with message:" << message;
    
    if (!m_currentClient || m_currentClient->state() != QLocalSocket::ConnectedState) {
        qCDebug(ipcServer) << "Client not connected, queueing message";
        queueMessage(message);
        return;
    }
    
    QJsonDocument doc(message);
    QByteArray data = doc.toJson(QJsonDocument::Compact);
    qCDebug(ipcServer) << "Sending to client:" << data;
    m_currentClient->write(data + "\n");  // Add newline for SplitParser
    m_currentClient->flush();
}

void IPCServer::sendErrorToClient(const QString &error)
{
    QJsonObject errorMessage;
    errorMessage["type"] = "error";
    errorMessage["error"] = error;
    sendMessageToClient(errorMessage);
}

bool IPCServer::checkRateLimit()
{
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    
    // Add current message timestamp
    m_messageTimestamps.enqueue(currentTime);
    
    // Remove timestamps older than the window
    while (!m_messageTimestamps.isEmpty() && 
           (currentTime - m_messageTimestamps.head()) > RATE_LIMIT_WINDOW_MS) {
        m_messageTimestamps.dequeue();
    }
    
    // Check if we exceed the rate limit
    if (m_messageTimestamps.size() > MAX_MESSAGES_PER_SECOND) {
        qCWarning(ipcServer) << "Rate limit exceeded:" << m_messageTimestamps.size() 
                           << "messages in last" << RATE_LIMIT_WINDOW_MS << "ms";
        return false;
    }
    
    return true;
}

void IPCServer::onShowAuthDialog(const QString &actionId, const QString &message, const QString &iconName, const QString &cookie)
{
    QJsonObject response;
    response["type"] = "show_auth_dialog";
    response["action_id"] = actionId;
    response["message"] = message;
    response["icon_name"] = iconName;
    response["cookie"] = cookie;
    
    sendMessageToClient(response);
}

void IPCServer::onAuthorizationResult(bool authorized, const QString &actionId)
{
    // Audit log the authorization result
    QString result = authorized ? "GRANTED" : "DENIED";
    SecurityManager::auditLog("AUTH_RESULT", QString("action=%1").arg(actionId), result);
    
    QJsonObject response;
    response["type"] = "authorization_result";
    response["authorized"] = authorized;
    response["action_id"] = actionId;
    
    sendMessageToClient(response);
}

void IPCServer::onAuthorizationError(const QString &error)
{
    // Audit log the authorization error
    SecurityManager::auditLog("AUTH_ERROR", QString("error=\"%1\"").arg(error), "ERROR");
    
    QJsonObject response;
    response["type"] = "authorization_error";
    response["error"] = error;
    
    sendMessageToClient(response);
}

void IPCServer::onShowPasswordRequest(const QString &actionId, const QString &request, bool echo, const QString &cookie)
{
    QJsonObject response;
    response["type"] = "password_request";
    response["action_id"] = actionId;
    response["request"] = request;
    response["echo"] = echo;
    response["cookie"] = cookie;
    
    sendMessageToClient(response);
}

void IPCServer::startHeartbeat()
{
    qCDebug(ipcServer) << "Starting heartbeat monitoring";
    m_heartbeatTimer->start();
}

void IPCServer::stopHeartbeat()
{
    qCDebug(ipcServer) << "Stopping heartbeat monitoring";
    m_heartbeatTimer->stop();
}

void IPCServer::resetSessionTimeout()
{
    // Reset session start time to extend the session
    m_sessionStartTime = SecurityManager::getCurrentTimestamp();
    qCDebug(ipcServer) << "Session timeout reset due to activity";
}

void IPCServer::onHeartbeatTimeout()
{
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    qint64 timeSinceLastHeartbeat = currentTime - m_lastHeartbeat;
    
    if (timeSinceLastHeartbeat > CONNECTION_TIMEOUT_MS) {
        qCWarning(ipcServer) << "Client heartbeat timeout after" << timeSinceLastHeartbeat << "ms";
        
        if (m_currentClient) {
            m_currentClient->disconnectFromServer();
        }
    }
}

void IPCServer::queueMessage(const QJsonObject &message)
{
    QString type = message["type"].toString();
    
    // Don't queue certain message types (heartbeat acks, errors, welcome)
    if (type == "heartbeat_ack" || type == "error" || type == "welcome") {
        qCDebug(ipcServer) << "Not queueing message of type:" << type;
        return;
    }
    
    // Limit queue size to prevent memory issues
    static constexpr int MAX_QUEUED_MESSAGES = 50;
    if (m_pendingMessages.size() >= MAX_QUEUED_MESSAGES) {
        qCWarning(ipcServer) << "Message queue full, dropping oldest message";
        m_pendingMessages.dequeue();
    }
    
    m_pendingMessages.enqueue(message);
    qCDebug(ipcServer) << "Queued message, queue size:" << m_pendingMessages.size();
}

void IPCServer::replayQueuedMessages()
{
    if (m_pendingMessages.isEmpty()) {
        return;
    }
    
    qCDebug(ipcServer) << "Replaying" << m_pendingMessages.size() << "queued messages";
    
    while (!m_pendingMessages.isEmpty()) {
        QJsonObject message = m_pendingMessages.dequeue();
        
        // Send directly to avoid re-queueing
        if (m_currentClient && m_currentClient->state() == QLocalSocket::ConnectedState) {
            QJsonDocument doc(message);
            QByteArray data = doc.toJson(QJsonDocument::Compact);
            qCDebug(ipcServer) << "Replaying queued message:" << data;
            m_currentClient->write(data + "\n");
        }
    }
    
    if (m_currentClient) {
        m_currentClient->flush();
    }
}

void IPCServer::onSessionTimeout()
{
    if (SecurityManager::isSessionExpired(m_sessionStartTime)) {
        qCWarning(ipcServer) << "Session timeout reached, disconnecting client";
        SecurityManager::auditLog("SESSION_TIMEOUT", "Maximum session duration exceeded", "DISCONNECTED");
        
        if (m_currentClient) {
            sendErrorToClient("Session timeout - please reconnect");
            m_currentClient->disconnectFromServer();
        }
    }
}

