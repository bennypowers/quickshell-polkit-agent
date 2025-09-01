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
#include <QDebug>
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
        qDebug() << "Using session subject for session:" << sessionId;
    } else {
        subject = PolkitQt1::UnixProcessSubject(getpid());
        qDebug() << "Using process subject for PID:" << getpid();
    }

    // Register as polkit agent
    bool success = registerListener(subject, "/quickshell/polkit/agent");

    if (success) {
        qDebug() << "Successfully registered as polkit agent";
        return true;
    } else {
        qCritical() << "Failed to register as polkit agent";
        return false;
    }
}

void PolkitWrapper::unregisterAgent()
{
    // The base class handles unregistration in its destructor
    qDebug() << "Polkit agent will be unregistered on destruction";
}

void PolkitWrapper::checkAuthorization(const QString &actionId, const QString &details)
{
    if (m_authority->hasError()) {
        emit authorizationError(QString("Polkit authority error: %1").arg(m_authority->errorDetails()));
        return;
    }

    m_currentActionId = actionId;
    
    qDebug() << "checkAuthorization called for action:" << actionId;
    
    // When used as an agent, we should NOT call m_authority->checkAuthorization() here
    // The polkit daemon will call our initiateAuthentication() method when needed
    // For now, just emit the show dialog signal for UI compatibility
    emit showAuthDialog(actionId, QString("Authentication required for %1").arg(actionId), "dialog-password", "");
}

void PolkitWrapper::cancelAuthorization()
{
    qDebug() << "Cancelling authorization check";
    
    // Cancel any active polkit sessions
    for (auto it = m_activePolkitSessions.begin(); it != m_activePolkitSessions.end(); ++it) {
        qDebug() << "Cancelling active session for cookie:" << it.key();
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
        qDebug() << "Authorization granted for" << m_currentActionId;
        break;
    case PolkitQt1::Authority::No:
        qDebug() << "Authorization denied for" << m_currentActionId;
        break;
    case PolkitQt1::Authority::Challenge:
        qDebug() << "Authorization requires challenge for" << m_currentActionId;
        break;
    default:
        qDebug() << "Unknown authorization result for" << m_currentActionId;
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
    qDebug() << "initiateAuthentication for" << actionId << "cookie:" << cookie;
    
    // Store the result for this session
    m_activeSessions[cookie] = result;
    
    // Create polkit session for the first identity
    if (!identities.isEmpty()) {
        PolkitQt1::Identity identity = identities.first();
        qDebug() << "Creating session for identity:" << identity.toString();
        
        PolkitQt1::Agent::Session *session = new PolkitQt1::Agent::Session(identity, cookie);
        m_activePolkitSessions[cookie] = session;
        
        // Connect session signals
        connect(session, &PolkitQt1::Agent::Session::completed,
                this, [this, cookie, actionId](bool gainedAuthorization) {
                    qDebug() << "Polkit session completed for cookie:" << cookie << "authorized:" << gainedAuthorization;
                    
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
                    qDebug() << "Session password request for cookie:" << cookie;
                    emit showPasswordRequest(actionId, request, echo, cookie);
                });
        
        connect(session, &PolkitQt1::Agent::Session::showError,
                this, [this, cookie, actionId](const QString &text) {
                    qWarning() << "Session error for cookie:" << cookie << "error:" << text;
                    
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
                    qDebug() << "Session info:" << text;
                });
        
        // Session created but not initiated yet - wait for user action
    }
    
    // Show auth dialog
    emit showAuthDialog(actionId, message, iconName, cookie);
}

bool PolkitWrapper::initiateAuthenticationFinish()
{
    // This method is part of the PolkitQt1::Agent::Listener interface
    // but is not used in our implementation since we complete results
    // directly in the session completion handlers
    qDebug() << "initiateAuthenticationFinish called (no-op)";
    return true;
}

void PolkitWrapper::cancelAuthentication()
{
    qDebug() << "Polkit agent: authentication cancelled";
    
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
        qWarning() << "No active polkit session for cookie:" << cookie;
        return;
    }
    
    PolkitQt1::Agent::Session *session = sessionIt.value();
    
    if (response.isEmpty()) {
        // Empty response means start FIDO authentication
        qDebug() << "Starting FIDO authentication for cookie:" << cookie;
        session->initiate();
    } else {
        // Password authentication - just submit response to existing session
        qDebug() << "Submitting password response for cookie:" << cookie;
        session->setResponse(response);
    }
}


