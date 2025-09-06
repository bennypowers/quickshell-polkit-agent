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

#include "polkit-wrapper.h"
#include <polkitqt1-subject.h>
#include <polkitqt1-details.h>
#include <QDebug>
#include <QRegularExpression>
#include <QFile>
#include "logging.h"
#include <QTimer>
#include <unistd.h>

PolkitWrapper::PolkitWrapper(QObject *parent)
    : PolkitQt1::Agent::Listener(parent)
    , m_authority(PolkitQt1::Authority::instance())
{
    // Connect authority signals
    connect(m_authority, &PolkitQt1::Authority::checkAuthorizationFinished,
            this, &PolkitWrapper::onCheckAuthorizationFinished);
}

PolkitWrapper::~PolkitWrapper()
{
    unregisterAgent();
}

bool PolkitWrapper::registerAgent()
{
    // Create subject for current session
    QString sessionId = qgetenv("XDG_SESSION_ID");
    PolkitQt1::Subject subject;
    
    if (!sessionId.isEmpty()) {
        subject = PolkitQt1::UnixSessionSubject(sessionId);
        qCDebug(polkitAgent) << "Using session subject for session:" << sessionId;
    } else {
        subject = PolkitQt1::UnixProcessSubject(getpid());
        qCDebug(polkitAgent) << "Using process subject for PID:" << getpid();
    }

    // Register as polkit agent
    bool success = registerListener(subject, "/quickshell/polkit/agent");

    if (success) {
        qCDebug(polkitAgent) << "Successfully registered as polkit agent";
        return true;
    } else {
        qCritical() << "Failed to register as polkit agent";
        return false;
    }
}

void PolkitWrapper::unregisterAgent()
{
    // The base class handles unregistration in its destructor
    qCDebug(polkitAgent) << "Polkit agent will be unregistered on destruction";
}

void PolkitWrapper::checkAuthorization(const QString &actionId, const QString &details)
{
    if (m_authority->hasError()) {
        emit authorizationError(QString("Polkit authority error: %1").arg(m_authority->errorDetails()));
        return;
    }

    m_currentActionId = actionId;
    
    qCDebug(polkitAgent) << "checkAuthorization called for action:" << actionId;
    
    // When used as an agent, we should NOT call m_authority->checkAuthorization() here
    // The polkit daemon will call our initiateAuthentication() method when needed
    // For now, just emit the show dialog signal for UI compatibility
    emit showAuthDialog(actionId, QString("Authentication required for %1").arg(actionId), "dialog-password", "");
}

void PolkitWrapper::cancelAuthorization()
{
    qCDebug(polkitAgent) << "Cancelling authorization check";
    
    // Cancel any active polkit sessions
    for (auto it = m_activePolkitSessions.begin(); it != m_activePolkitSessions.end(); ++it) {
        qCDebug(polkitSensitive) << "Cancelling active session for cookie:" << it.key();
        it.value()->cancel();
        it.value()->deleteLater();
    }
    m_activePolkitSessions.clear();
    
    // Cancel the authority check
    m_authority->checkAuthorizationCancel();
    
    // Complete any pending results
    for (auto it = m_activeSessions.begin(); it != m_activeSessions.end(); ++it) {
        it.value()->setError("Cancelled by user");
        it.value()->setCompleted();
    }
    m_activeSessions.clear();
    
    emit authorizationResult(false, m_currentActionId);
}

void PolkitWrapper::onCheckAuthorizationFinished(PolkitQt1::Authority::Result result)
{
    bool authorized = false;
    
    switch (result) {
    case PolkitQt1::Authority::Yes:
        authorized = true;
        qCDebug(polkitAgent) << "Authorization granted for" << m_currentActionId;
        break;
    case PolkitQt1::Authority::No:
        qCDebug(polkitAgent) << "Authorization denied for" << m_currentActionId;
        break;
    case PolkitQt1::Authority::Challenge:
        qCDebug(polkitAgent) << "Authorization requires challenge for" << m_currentActionId;
        break;
    default:
        qCDebug(polkitAgent) << "Unknown authorization result for" << m_currentActionId;
        emit authorizationError("Unknown authorization result");
        return;
    }
    
    emit authorizationResult(authorized, m_currentActionId);
}

// PolkitQt1::Agent::Listener interface implementation
void PolkitWrapper::initiateAuthentication(const QString &actionId,
                                          const QString &message,
                                          const QString &iconName,
                                          const PolkitQt1::Details &details,
                                          const QString &cookie,
                                          const PolkitQt1::Identity::List &identities,
                                          PolkitQt1::Agent::AsyncResult *result)
{
    qCDebug(polkitAgent) << "initiateAuthentication for" << actionId;
    qCDebug(polkitSensitive) << "initiateAuthentication cookie:" << cookie;
    
    // Store the result for this session
    m_activeSessions[cookie] = result;
    
    // Create polkit session for the first identity
    if (!identities.isEmpty()) {
        PolkitQt1::Identity identity = identities.first();
        qCDebug(polkitAgent) << "Creating session for identity:" << identity.toString();
        
        PolkitQt1::Agent::Session *session = new PolkitQt1::Agent::Session(identity, cookie);
        m_activePolkitSessions[cookie] = session;
        
        // Connect session signals
        connect(session, &PolkitQt1::Agent::Session::completed,
                this, [this, cookie, actionId](bool gainedAuthorization) {
                    qCDebug(polkitAgent) << "Polkit session completed, authorized:" << gainedAuthorization;
                    qCDebug(polkitSensitive) << "Session cookie:" << cookie;
                    
                    // Complete the AsyncResult for polkit daemon
                    auto resultIt = m_activeSessions.find(cookie);
                    if (resultIt != m_activeSessions.end()) {
                        if (gainedAuthorization) {
                            resultIt.value()->setCompleted();
                        } else {
                            resultIt.value()->setError("Authentication failed");
                            resultIt.value()->setCompleted();
                        }
                        m_activeSessions.erase(resultIt);
                    }
                    
                    // Clean up session
                    auto sessionIt = m_activePolkitSessions.find(cookie);
                    if (sessionIt != m_activePolkitSessions.end()) {
                        sessionIt.value()->deleteLater();
                        m_activePolkitSessions.erase(sessionIt);
                    }
                    
                    emit authorizationResult(gainedAuthorization, actionId);
                });
        
        connect(session, &PolkitQt1::Agent::Session::request,
                this, [this, cookie, actionId](const QString &request, bool echo) {
                    qCDebug(polkitAgent) << "Session password request";
                    qCDebug(polkitSensitive) << "Password request for cookie:" << cookie;
                    emit showPasswordRequest(actionId, request, echo, cookie);
                });
        
        connect(session, &PolkitQt1::Agent::Session::showError,
                this, [this, cookie, actionId](const QString &text) {
                    qCWarning(polkitAgent) << "Session error:" << text;
                    qCDebug(polkitSensitive) << "Session error for cookie:" << cookie;
                    
                    // Complete the AsyncResult with error
                    auto resultIt = m_activeSessions.find(cookie);
                    if (resultIt != m_activeSessions.end()) {
                        resultIt.value()->setError(QString("Session error: %1").arg(text));
                        resultIt.value()->setCompleted();
                        m_activeSessions.erase(resultIt);
                    }
                    
                    // Clean up session on error
                    auto sessionIt = m_activePolkitSessions.find(cookie);
                    if (sessionIt != m_activePolkitSessions.end()) {
                        sessionIt.value()->deleteLater();
                        m_activePolkitSessions.erase(sessionIt);
                    }
                    
                    emit authorizationResult(false, actionId);
                });
        
        connect(session, &PolkitQt1::Agent::Session::showInfo,
                this, [this, cookie](const QString &text) {
                    qCDebug(polkitAgent) << "Session info:" << text;
                });
        
        // Session created but not initiated yet - wait for user action
    }
    
    // Transform message for user-friendly text
    QString transformedMessage = transformAuthMessage(actionId, message, details);
    
    // Show auth dialog
    emit showAuthDialog(actionId, transformedMessage, iconName, cookie);
}

bool PolkitWrapper::initiateAuthenticationFinish()
{
    // This method is part of the PolkitQt1::Agent::Listener interface
    // but is not used in our implementation since we complete results
    // directly in the session completion handlers
    qCDebug(polkitAgent) << "initiateAuthenticationFinish called (no-op)";
    return true;
}

void PolkitWrapper::cancelAuthentication()
{
    qCDebug(polkitAgent) << "Polkit agent: authentication cancelled";
    
    // Cancel all active sessions
    for (auto it = m_activeSessions.begin(); it != m_activeSessions.end(); ++it) {
        it.value()->setError("Authentication cancelled");
        it.value()->setCompleted();
    }
    m_activeSessions.clear();
}

void PolkitWrapper::submitAuthenticationResponse(const QString &cookie, const QString &response)
{
    auto sessionIt = m_activePolkitSessions.find(cookie);
    if (sessionIt == m_activePolkitSessions.end()) {
        qCWarning(polkitAgent) << "No active polkit session found";
        qCDebug(polkitSensitive) << "Missing session for cookie:" << cookie;
        return;
    }
    
    PolkitQt1::Agent::Session *session = sessionIt.value();
    
    if (response.isEmpty()) {
        // Empty response means start FIDO authentication
        qCDebug(polkitAgent) << "Starting FIDO authentication";
        qCDebug(polkitSensitive) << "FIDO auth for cookie:" << cookie;
        session->initiate();
    } else {
        // Password authentication - just submit response to existing session
        qCDebug(polkitAgent) << "Submitting password response";
        qCDebug(polkitSensitive) << "Password response for cookie:" << cookie;
        session->setResponse(response);
    }
}

QString PolkitWrapper::transformAuthMessage(const QString &actionId, const QString &message, const PolkitQt1::Details &details)
{
    // Check if message transformation is disabled
    QString disableTransform = qgetenv("QUICKSHELL_POLKIT_DISABLE_TRANSFORM");
    if (!disableTransform.isEmpty() && disableTransform != "0" && disableTransform.toLower() != "false") {
        return message;
    }
    
    // Check if this is a systemd run0 (transient service) request
    if (actionId == "org.freedesktop.systemd1.manage-units") {
        qCDebug(polkitAgent) << "Checking systemd manage-units action, message:" << message;
        
        // Check if the message indicates a transient service (broader pattern matching)
        if (message.contains("transient", Qt::CaseInsensitive)) {
            
            qCDebug(polkitAgent) << "Detected systemd run0 authorization request";
            
            // Try to extract command information using PID from polkit details
            QString commandInfo;
            QStringList detailKeys = details.keys();
            qCDebug(polkitAgent) << "Available detail keys:" << detailKeys;
            
            // Get the subject PID to extract command
            QString subjectPid = details.lookup("polkit.subject-pid");
            if (!subjectPid.isEmpty()) {
                qCDebug(polkitAgent) << "Attempting to get command for PID:" << subjectPid;
                
                // Try to read the command from /proc/PID/cmdline
                QString cmdlinePath = QString("/proc/%1/cmdline").arg(subjectPid);
                QFile cmdlineFile(cmdlinePath);
                if (cmdlineFile.open(QIODevice::ReadOnly)) {
                    QByteArray cmdlineData = cmdlineFile.readAll();
                    cmdlineFile.close();
                    
                    // /proc/PID/cmdline has null-separated arguments
                    QStringList args = QString::fromUtf8(cmdlineData).split('\0', Qt::SkipEmptyParts);
                    qCDebug(polkitAgent) << "Command line args:" << args;
                    
                    if (!args.isEmpty()) {
                        // Get the command name (remove path)
                        QString command = args.first();
                        if (command.contains('/')) {
                            command = command.split('/').last();
                        }
                        
                        // If it's systemd-run or run0, try to get the actual command
                        if (command == "systemd-run" || command == "run0") {
                            qCDebug(polkitAgent) << "Found systemd-run/run0, extracting target command";
                            // Look for the actual command after systemd-run options
                            bool foundCommand = false;
                            for (int i = 1; i < args.size(); ++i) {
                                const QString &arg = args[i];
                                // Skip systemd-run options
                                if (arg.startsWith("--") || arg.startsWith("-")) {
                                    // Skip option and its value if it takes one
                                    if (arg.contains("=")) continue;
                                    if (i + 1 < args.size() && !args[i + 1].startsWith("-")) {
                                        i++; // Skip option value
                                    }
                                    continue;
                                }
                                // Found the actual command
                                command = arg;
                                if (command.contains('/')) {
                                    command = command.split('/').last();
                                }
                                foundCommand = true;
                                qCDebug(polkitAgent) << "Found target command:" << command;
                                break;
                            }
                            if (!foundCommand && args.size() > 1) {
                                command = args.last(); // Fallback to last argument
                                if (command.contains('/')) {
                                    command = command.split('/').last();
                                }
                                qCDebug(polkitAgent) << "Using fallback command:" << command;
                            }
                        }
                        
                        commandInfo = command;
                        qCDebug(polkitAgent) << "Final extracted command:" << commandInfo;
                    }
                } else {
                    qCDebug(polkitAgent) << "Could not read cmdline for PID:" << subjectPid;
                }
            }
            
            // Check for custom message template from environment
            QString customTemplate = qgetenv("QUICKSHELL_POLKIT_RUN0_MESSAGE");
            
            // Generate user-friendly message
            if (!customTemplate.isEmpty()) {
                // Use custom template, replace %1 with command if available
                if (!commandInfo.isEmpty() && commandInfo != actionId) {
                    return customTemplate.arg(commandInfo);
                } else {
                    // Remove %1 placeholder if no command info available
                    return customTemplate.replace("%1", "command");
                }
            } else if (!commandInfo.isEmpty() && commandInfo != actionId) {
                return QString("Authentication required to run '%1' with elevated privileges").arg(commandInfo);
            } else {
                return "Authentication required to run command with elevated privileges";
            }
        }
    }
    
    // For non-run0 requests, return original message
    return message;
}


