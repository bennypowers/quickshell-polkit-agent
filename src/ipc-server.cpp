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
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include "logging.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTimer>
#include <QDateTime>

IPCServer::IPCServer(PolkitWrapper *polkitWrapper, QObject *parent)
    : QObject(parent)
    , m_server(new QLocalServer(this))
    , m_currentClient(nullptr)
    , m_polkitWrapper(polkitWrapper)
    , m_rateLimitTimer(new QTimer(this))
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
}

IPCServer::~IPCServer()
{
    if (m_server->isListening()) {
        m_server->close();
    }
}

bool IPCServer::startServer(const QString &socketName)
{
    // Create socket in user runtime directory
    QString socketPath = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (socketPath.isEmpty()) {
        socketPath = QString("/tmp/quickshell-polkit-%1").arg(getuid());
    }
    
    // Create the quickshell-polkit subdirectory
    QString socketDir = QString("%1/quickshell-polkit").arg(socketPath);
    QDir().mkpath(socketDir);
    
    QString fullSocketPath = QString("%1/%2").arg(socketDir, socketName);
    
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
    
    // Send welcome message to keep connection alive
    QJsonObject welcome;
    welcome["type"] = "welcome";
    welcome["message"] = "Connected to quickshell-polkit-agent";
    sendMessageToClient(welcome);
}

void IPCServer::onClientDisconnected()
{
    if (m_currentClient) {
        qCDebug(ipcServer) << "Quickshell client disconnected, error:" << m_currentClient->errorString();
        m_currentClient->deleteLater();
        m_currentClient = nullptr;
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
        return;
    }
    
    // Validate message before processing
    ValidationResult validation = MessageValidator::validateMessage(message);
    if (!validation.valid) {
        qCWarning(ipcServer) << "Invalid message from client:" << validation.error;
        sendErrorToClient("Invalid message: " + validation.error);
        return;
    }
    
    QString type = message["type"].toString();
    qCDebug(ipcServer) << "Received valid client message type:" << type;
    
    if (type == "check_authorization") {
        QString actionId = message["action_id"].toString();
        QString details = message["details"].toString();
        
        qCDebug(ipcServer) << "Client requesting authorization for:" << actionId;
        m_polkitWrapper->checkAuthorization(actionId, details);
        
    } else if (type == "cancel_authorization") {
        qCDebug(ipcServer) << "Client cancelling authorization";
        m_polkitWrapper->cancelAuthorization();
        
    } else if (type == "submit_authentication") {
        QString cookie = message["cookie"].toString();
        QString response = message["response"].toString();
        
        qCDebug(ipcServer) << "Client submitting authentication, response length:" << response.length();
        qCDebug(polkitSensitive) << "Auth submission for cookie:" << cookie;
        m_polkitWrapper->submitAuthenticationResponse(cookie, response);
        
    } else {
        // This should never happen due to validation, but keep as safety net
        qCWarning(ipcServer) << "Unknown message type from client:" << type;
        sendErrorToClient("Unknown message type: " + type);
    }
}

void IPCServer::sendMessageToClient(const QJsonObject &message)
{
    qCDebug(ipcServer) << "sendMessageToClient called with message:" << message;
    
    if (!m_currentClient) {
        qCDebug(ipcServer) << "No client connected";
        return;
    }
    
    if (m_currentClient->state() != QLocalSocket::ConnectedState) {
        qCDebug(ipcServer) << "Client not in connected state, current state:" << m_currentClient->state();
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
    QJsonObject response;
    response["type"] = "authorization_result";
    response["authorized"] = authorized;
    response["action_id"] = actionId;
    
    sendMessageToClient(response);
}

void IPCServer::onAuthorizationError(const QString &error)
{
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

