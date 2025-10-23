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
#include <QProcess>
#include "logging.h"
#include <QTimer>
#include <unistd.h>

PolkitWrapper::PolkitWrapper(QObject *parent)
    : PolkitQt1::Agent::Listener(parent)
    , m_authority(PolkitQt1::Authority::instance())
    , m_nfcReaderPresent(false)
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

    // Cancel the authority check
    m_authority->checkAuthorizationCancel();

    // Cancel all active sessions using unified cleanup
    QStringList cookiesToCleanup = m_sessions.keys();
    for (const QString &cookie : cookiesToCleanup) {
        SessionState *session = getSession(cookie);
        if (session) {
            setState(cookie, AuthenticationState::CANCELLED);
            cleanupSession(cookie);
        }
    }

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

    // Detect NFC reader presence
    m_nfcReaderPresent = detectNfcReader();

    // Create new session state
    SessionState sessionState;
    sessionState.cookie = cookie;
    sessionState.actionId = actionId;
    sessionState.result = result;
    sessionState.state = AuthenticationState::IDLE;
    m_sessions[cookie] = sessionState;

    // Set initial state
    setState(cookie, AuthenticationState::INITIATED);

    // Create polkit session for the first identity
    if (!identities.isEmpty()) {
        PolkitQt1::Identity identity = identities.first();
        qCDebug(polkitAgent) << "Creating session for identity:" << identity.toString();

        PolkitQt1::Agent::Session *pamSession = new PolkitQt1::Agent::Session(identity, cookie);

        // Store PAM session in our SessionState
        SessionState *state = getSession(cookie);
        if (state) {
            state->session = pamSession;
        }
        
        // Connect session signals
        connect(pamSession, &PolkitQt1::Agent::Session::completed,
                this, [this, cookie, actionId](bool gainedAuthorization) {
                    qCDebug(polkitAgent) << "Polkit session completed, authorized:" << gainedAuthorization;
                    qCDebug(polkitSensitive) << "Session cookie:" << cookie;

                    // Cancel any active FIDO timeout
                    cancelFidoTimeout(cookie);

                    // Update state
                    if (gainedAuthorization) {
                        setState(cookie, AuthenticationState::COMPLETED);
                    } else {
                        SessionState *session = getSession(cookie);
                        if (session) {
                            session->retryCount++;
                            qCDebug(polkitAgent) << "Authentication failed, retry count:" << session->retryCount
                                                 << "/" << MAX_AUTH_RETRIES;

                            if (session->retryCount >= MAX_AUTH_RETRIES) {
                                qCWarning(polkitAgent) << "Maximum authentication attempts reached for" << cookie;
                                setState(cookie, AuthenticationState::MAX_RETRIES_EXCEEDED);

                                // Emit error with default message
                                QString defaultMsg = getDefaultErrorMessage(AuthenticationState::MAX_RETRIES_EXCEEDED, session->method);
                                emit authenticationError(cookie, AuthenticationState::MAX_RETRIES_EXCEEDED,
                                                        session->method, defaultMsg,
                                                        QString("Retry count: %1/%2").arg(session->retryCount).arg(MAX_AUTH_RETRIES));
                            } else {
                                setState(cookie, AuthenticationState::AUTHENTICATION_FAILED);

                                // Emit error with default message
                                QString defaultMsg = getDefaultErrorMessage(AuthenticationState::AUTHENTICATION_FAILED, session->method);
                                emit authenticationError(cookie, AuthenticationState::AUTHENTICATION_FAILED,
                                                        session->method, defaultMsg,
                                                        QString("Retry count: %1/%2").arg(session->retryCount).arg(MAX_AUTH_RETRIES));
                            }
                        }
                    }

                    // Complete the AsyncResult for polkit daemon
                    SessionState *session = getSession(cookie);
                    if (session && session->result) {
                        if (gainedAuthorization) {
                            session->result->setCompleted();
                        } else {
                            session->result->setError("Authentication failed");
                            session->result->setCompleted();
                        }
                    }

                    emit authorizationResult(gainedAuthorization, actionId);

                    // Clean up session
                    cleanupSession(cookie);
                });

        connect(pamSession, &PolkitQt1::Agent::Session::request,
                this, [this, cookie, actionId](const QString &request, bool echo) {
                    qCDebug(polkitAgent) << "Session request:" << request << "echo:" << echo;
                    qCDebug(polkitSensitive) << "Request for cookie:" << cookie;

                    SessionState *session = getSession(cookie);
                    if (!session || !session->session) {
                        qCWarning(polkitAgent) << "Session not found for cookie in request handler";
                        return;
                    }

                    // Enforce max retries - refuse to continue if exceeded
                    if (session->state == AuthenticationState::MAX_RETRIES_EXCEEDED) {
                        qCWarning(polkitAgent) << "Ignoring PAM request - max retries exceeded for" << cookie;
                        // Don't respond to PAM - this will cause the session to fail
                        return;
                    }

                    // Check if NFC reader is present and we haven't tried NFC for this session yet
                    if (m_nfcReaderPresent && !session->nfcAttempted) {
                        qCDebug(polkitAgent) << "NFC reader present, auto-attempting FIDO authentication";
                        setState(cookie, AuthenticationState::TRYING_FIDO);
                        setMethod(cookie, AuthenticationMethod::FIDO);

                        // Mark that we've attempted NFC for this session
                        session->nfcAttempted = true;

                        // Start FIDO timeout - if user doesn't tap within 15s, fallback to password
                        startFidoTimeout(cookie);

                        // Auto-respond with empty string to let pam_u2f proceed with FIDO check
                        session->session->setResponse("");
                    } else {
                        // Either no NFC reader, or NFC already tried and failed - show password prompt
                        qCDebug(polkitAgent) << "Password request from PAM - NFC reader:" << m_nfcReaderPresent
                                             << "already attempted:" << session->nfcAttempted;

                        if (session->nfcAttempted) {
                            // FIDO failed, transitioning to password
                            // Cancel timeout if it's still running
                            cancelFidoTimeout(cookie);

                            setState(cookie, AuthenticationState::FIDO_FAILED);
                            emit authenticationMethodFailed(cookie, AuthenticationMethod::FIDO, "FIDO authentication failed");
                        }

                        setState(cookie, AuthenticationState::WAITING_FOR_PASSWORD);
                        setMethod(cookie, AuthenticationMethod::PASSWORD);
                        emit showPasswordRequest(actionId, request, echo, cookie);
                    }
                });

        connect(pamSession, &PolkitQt1::Agent::Session::showError,
                this, [this, cookie, actionId](const QString &text) {
                    qCWarning(polkitAgent) << "Session error:" << text;
                    qCDebug(polkitSensitive) << "Session error for cookie:" << cookie;

                    setState(cookie, AuthenticationState::ERROR);

                    SessionState *session = getSession(cookie);
                    if (session) {
                        // Emit error with default message
                        QString defaultMsg = getDefaultErrorMessage(AuthenticationState::ERROR, session->method);
                        emit authenticationError(cookie, AuthenticationState::ERROR,
                                                session->method, defaultMsg, text);

                        if (session->result) {
                            session->result->setError(QString("Session error: %1").arg(text));
                            session->result->setCompleted();
                        }
                    }

                    emit authorizationResult(false, actionId);

                    cleanupSession(cookie);
                });

        connect(pamSession, &PolkitQt1::Agent::Session::showInfo,
                this, [this, cookie](const QString &text) {
                    qCDebug(polkitAgent) << "Session info:" << text;
                });

        /*
         * Initiate PAM session immediately (GDM pattern)
         *
         * GDM calls pam_authenticate() right away, and the PAM conversation
         * starts. PAM will call our request() handler when it needs input.
         *
         * See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session-worker.c:1342
         * SPDX-License-Identifier: GPL-2.0-or-later (for GDM reference pattern)
         */
        qCDebug(polkitAgent) << "Starting PAM authentication session for" << cookie;
        pamSession->initiate();
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
    qCDebug(polkitAgent) << "Polkit agent: authentication cancelled (Listener interface)";

    // Cancel all active sessions using unified cleanup
    QStringList cookiesToCleanup = m_sessions.keys();
    for (const QString &cookie : cookiesToCleanup) {
        setState(cookie, AuthenticationState::CANCELLED);
        cleanupSession(cookie);
    }
}

void PolkitWrapper::submitAuthenticationResponse(const QString &cookie, const QString &response)
{
    SessionState *session = getSession(cookie);
    if (!session || !session->session) {
        qCWarning(polkitAgent) << "No active polkit session found";
        qCDebug(polkitSensitive) << "Missing session for cookie:" << cookie;
        return;
    }

    /*
     * Enforce max retries - prevent faillocks
     *
     * If user has failed too many times, refuse to accept more attempts.
     * This prevents PAM from locking the account.
     */
    if (session->state == AuthenticationState::MAX_RETRIES_EXCEEDED) {
        qCWarning(polkitAgent) << "Rejecting authentication response - max retries exceeded";
        qCDebug(polkitSensitive) << "Rejected cookie:" << cookie;

        // Emit comprehensive error signal
        QString defaultMsg = getDefaultErrorMessage(AuthenticationState::MAX_RETRIES_EXCEEDED, session->method);
        emit authenticationError(cookie, AuthenticationState::MAX_RETRIES_EXCEEDED,
                                session->method, defaultMsg,
                                "User attempted to submit response after max retries");

        // Also emit simple error for backwards compatibility
        emit authorizationError(defaultMsg);
        return;
    }

    /*
     * Submit user response to PAM
     *
     * Note: We no longer call initiate() here - that happens in
     * initiateAuthentication() following GDM's pattern. This method
     * just submits the user's response to an already-running PAM conversation.
     */
    qCDebug(polkitAgent) << "Submitting authentication response";
    qCDebug(polkitSensitive) << "Response for cookie:" << cookie;

    setState(cookie, AuthenticationState::AUTHENTICATING);
    setMethod(cookie, AuthenticationMethod::PASSWORD);
    session->session->setResponse(response);
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

bool PolkitWrapper::detectNfcReader()
{
    QProcess lsusb;
    lsusb.start("lsusb");

    if (!lsusb.waitForFinished(1000)) {
        qCWarning(polkitAgent) << "lsusb command timed out";
        return false;
    }

    QString output = QString::fromUtf8(lsusb.readAllStandardOutput()).toLower();

    // Check for ACR122U NFC reader (vendor ID 072f:)
    bool nfcPresent = output.contains("072f:") || output.contains("acr122");

    qCDebug(polkitAgent) << "NFC reader detection:" << (nfcPresent ? "ACR122U found" : "No NFC reader");

    return nfcPresent;
}

// =============================================================================
// State Machine Implementation
// =============================================================================

/*
 * Get session state by cookie
 *
 * Pattern inspired by GDM's find_conversation_by_name
 * See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session.c
 */
SessionState* PolkitWrapper::getSession(const QString &cookie)
{
    auto it = m_sessions.find(cookie);
    if (it != m_sessions.end()) {
        return &it.value();
    }
    return nullptr;
}

const SessionState* PolkitWrapper::getSession(const QString &cookie) const
{
    auto it = m_sessions.find(cookie);
    if (it != m_sessions.end()) {
        return &it.value();
    }
    return nullptr;
}

/*
 * Set authentication state for a session
 *
 * Pattern inspired by GDM's gdm_session_worker_set_state
 * See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session-worker.c
 */
void PolkitWrapper::setState(const QString &cookie, AuthenticationState newState)
{
    SessionState *session = getSession(cookie);
    if (!session) {
        qCWarning(polkitAgent) << "Attempted to set state for non-existent session:" << cookie;
        return;
    }

    AuthenticationState oldState = session->state;
    if (oldState == newState) {
        return;  // No change
    }

    session->state = newState;
    qCDebug(polkitAgent) << "State transition for" << cookie << ":"
                         << stateToString(oldState) << "→" << stateToString(newState);

    emit authenticationStateChanged(cookie, newState);
}

/*
 * Set authentication method for a session
 */
void PolkitWrapper::setMethod(const QString &cookie, AuthenticationMethod method)
{
    SessionState *session = getSession(cookie);
    if (!session) {
        qCWarning(polkitAgent) << "Attempted to set method for non-existent session:" << cookie;
        return;
    }

    AuthenticationMethod oldMethod = session->method;
    if (oldMethod == method) {
        return;  // No change
    }

    session->method = method;
    qCDebug(polkitAgent) << "Method changed for" << cookie << ":"
                         << methodToString(oldMethod) << "→" << methodToString(method);

    emit authenticationMethodChanged(cookie, method);
}

/*
 * Cleanup session resources
 *
 * Unified cleanup pattern inspired by GDM's free_conversation
 * See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session.c
 */
void PolkitWrapper::cleanupSession(const QString &cookie)
{
    SessionState *session = getSession(cookie);
    if (!session) {
        return;  // Already cleaned up
    }

    qCDebug(polkitAgent) << "Cleaning up session:" << cookie
                         << "in state:" << stateToString(session->state);

    // Cancel any active FIDO timeout
    cancelFidoTimeout(cookie);

    // Clean up PAM session
    if (session->session) {
        session->session->cancel();
        session->session->deleteLater();
        session->session = nullptr;
    }

    // Complete async result if still pending
    if (session->result) {
        // Only complete if not already completed
        if (session->state != AuthenticationState::COMPLETED) {
            session->result->setError("Session cleaned up");
            session->result->setCompleted();
        }
        session->result = nullptr;
    }

    // Remove from map
    m_sessions.remove(cookie);

    qCDebug(polkitAgent) << "Session cleanup complete for:" << cookie;
}

// =============================================================================
// State Inspection Methods
// =============================================================================

AuthenticationState PolkitWrapper::authenticationState(const QString &cookie) const
{
    if (cookie.isEmpty()) {
        // Return global state (first active session or IDLE)
        if (m_sessions.isEmpty()) {
            return AuthenticationState::IDLE;
        }
        return m_sessions.first().state;
    }

    const SessionState *session = getSession(cookie);
    return session ? session->state : AuthenticationState::IDLE;
}

AuthenticationMethod PolkitWrapper::authenticationMethod(const QString &cookie) const
{
    const SessionState *session = getSession(cookie);
    return session ? session->method : AuthenticationMethod::NONE;
}

bool PolkitWrapper::hasActiveSessions() const
{
    return !m_sessions.isEmpty();
}

int PolkitWrapper::sessionRetryCount(const QString &cookie) const
{
    const SessionState *session = getSession(cookie);
    return session ? session->retryCount : 0;
}

// =============================================================================
// Helper Methods
// =============================================================================

QString PolkitWrapper::stateToString(AuthenticationState state) const
{
    switch (state) {
    case AuthenticationState::IDLE: return "IDLE";
    case AuthenticationState::INITIATED: return "INITIATED";
    case AuthenticationState::TRYING_FIDO: return "TRYING_FIDO";
    case AuthenticationState::FIDO_FAILED: return "FIDO_FAILED";
    case AuthenticationState::WAITING_FOR_PASSWORD: return "WAITING_FOR_PASSWORD";
    case AuthenticationState::AUTHENTICATING: return "AUTHENTICATING";
    case AuthenticationState::AUTHENTICATION_FAILED: return "AUTHENTICATION_FAILED";
    case AuthenticationState::MAX_RETRIES_EXCEEDED: return "MAX_RETRIES_EXCEEDED";
    case AuthenticationState::COMPLETED: return "COMPLETED";
    case AuthenticationState::CANCELLED: return "CANCELLED";
    case AuthenticationState::ERROR: return "ERROR";
    }
    return "UNKNOWN";
}

QString PolkitWrapper::methodToString(AuthenticationMethod method) const
{
    switch (method) {
    case AuthenticationMethod::NONE: return "NONE";
    case AuthenticationMethod::FIDO: return "FIDO";
    case AuthenticationMethod::PASSWORD: return "PASSWORD";
    }
    return "UNKNOWN";
}

#ifdef BUILD_TESTING
// =============================================================================
// Test-Only Methods
// =============================================================================

/*
 * Trigger authentication for testing
 *
 * This simulates polkit daemon calling initiateAuthentication().
 * Only available when BUILD_TESTING is defined.
 */
void PolkitWrapper::testTriggerAuthentication(const QString &actionId,
                                             const QString &message,
                                             const QString &iconName,
                                             const QString &cookie)
{
    // Create test identity (current user)
    uid_t uid = getuid();
    PolkitQt1::Identity identity = PolkitQt1::UnixUserIdentity(uid);
    PolkitQt1::Identity::List identities;
    identities << identity;

    // Create empty details
    PolkitQt1::Details details;

    // For testing, we pass nullptr for AsyncResult
    // The code must handle nullptr safely (it already does in most places)
    PolkitQt1::Agent::AsyncResult *result = nullptr;

    // Call protected initiateAuthentication method
    initiateAuthentication(actionId, message, iconName, details, cookie, identities, result);
}
#endif

// =============================================================================
// Error Message Generation
// =============================================================================

/*
 * Get default user-friendly error message
 *
 * Inspired by GDM's get_friendly_error_message pattern
 * See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session-worker.c:846
 * SPDX-License-Identifier: GPL-2.0-or-later (for GDM reference pattern)
 *
 * Provides default messages that QML can use or override.
 */
QString PolkitWrapper::getDefaultErrorMessage(AuthenticationState state, AuthenticationMethod method) const
{
    switch (state) {
    case AuthenticationState::MAX_RETRIES_EXCEEDED:
        // GDM pattern: Different messages per authentication method
        if (method == AuthenticationMethod::PASSWORD) {
            return "You reached the maximum password authentication attempts. Please try another method.";
        } else if (method == AuthenticationMethod::FIDO) {
            return "You reached the maximum security key attempts. Please try password authentication.";
        }
        return "You reached the maximum authentication attempts. Please try again later.";

    case AuthenticationState::AUTHENTICATION_FAILED:
        // GDM pattern: Method-specific friendly messages
        if (method == AuthenticationMethod::PASSWORD) {
            return "Incorrect password. Please try again.";
        } else if (method == AuthenticationMethod::FIDO) {
            return "Security key authentication failed. Please try again.";
        }
        return "Authentication failed. Please try again.";

    case AuthenticationState::FIDO_FAILED:
        return "Security key authentication timed out or failed. Please enter your password.";

    case AuthenticationState::ERROR:
        return "An error occurred during authentication. Please try again.";

    case AuthenticationState::CANCELLED:
        return "Authentication was cancelled.";

    // States that shouldn't produce user-facing errors
    case AuthenticationState::IDLE:
    case AuthenticationState::INITIATED:
    case AuthenticationState::TRYING_FIDO:
    case AuthenticationState::WAITING_FOR_PASSWORD:
    case AuthenticationState::AUTHENTICATING:
    case AuthenticationState::COMPLETED:
        return "";  // No error for these states
    }

    return "An unexpected error occurred.";
}

// =============================================================================
// FIDO Timeout Handling
// =============================================================================

/*
 * Start FIDO timeout timer
 *
 * If user doesn't tap their security key within timeout, we'll automatically
 * fall back to password authentication. This prevents indefinite hangs.
 */
void PolkitWrapper::startFidoTimeout(const QString &cookie)
{
    SessionState *session = getSession(cookie);
    if (!session) {
        qCWarning(polkitAgent) << "Cannot start FIDO timeout for non-existent session:" << cookie;
        return;
    }

    // Clean up any existing timer first
    if (session->fidoTimeoutTimer) {
        session->fidoTimeoutTimer->stop();
        session->fidoTimeoutTimer->deleteLater();
        session->fidoTimeoutTimer = nullptr;
    }

    // Create new single-shot timer
    session->fidoTimeoutTimer = new QTimer(this);
    session->fidoTimeoutTimer->setSingleShot(true);
    session->fidoTimeoutTimer->setInterval(FIDO_TIMEOUT_MS);

    connect(session->fidoTimeoutTimer, &QTimer::timeout, this, [this, cookie]() {
        onFidoTimeout(cookie);
    });

    session->fidoTimeoutTimer->start();

    qCDebug(polkitAgent) << "Started FIDO timeout for" << cookie
                         << "- will timeout in" << FIDO_TIMEOUT_MS << "ms";
}

/*
 * Cancel FIDO timeout timer
 *
 * Called when FIDO succeeds/fails before timeout, or when session is cancelled.
 */
void PolkitWrapper::cancelFidoTimeout(const QString &cookie)
{
    SessionState *session = getSession(cookie);
    if (!session || !session->fidoTimeoutTimer) {
        return;  // No timer to cancel
    }

    qCDebug(polkitAgent) << "Cancelling FIDO timeout for" << cookie;

    session->fidoTimeoutTimer->stop();
    session->fidoTimeoutTimer->deleteLater();
    session->fidoTimeoutTimer = nullptr;
}

/*
 * Handle FIDO timeout
 *
 * User didn't tap their security key in time. Fall back to password.
 */
void PolkitWrapper::onFidoTimeout(const QString &cookie)
{
    qCDebug(polkitAgent) << "FIDO timeout occurred for" << cookie;

    SessionState *session = getSession(cookie);
    if (!session) {
        qCWarning(polkitAgent) << "FIDO timeout for non-existent session:" << cookie;
        return;
    }

    // Clean up timer
    if (session->fidoTimeoutTimer) {
        session->fidoTimeoutTimer->deleteLater();
        session->fidoTimeoutTimer = nullptr;
    }

    // Only handle timeout if we're still waiting for FIDO
    if (session->state != AuthenticationState::TRYING_FIDO) {
        qCDebug(polkitAgent) << "Ignoring FIDO timeout - no longer in TRYING_FIDO state";
        return;
    }

    // Transition to FIDO_FAILED state
    setState(cookie, AuthenticationState::FIDO_FAILED);
    emit authenticationMethodFailed(cookie, AuthenticationMethod::FIDO,
                                   "Security key timeout - no response within 15 seconds");

    // PAM will call our request() handler again, which will show password prompt
    // We don't need to do anything else here - the PAM conversation continues
}


