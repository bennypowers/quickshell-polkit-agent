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

#pragma once

#include <QObject>
#include <QString>
#include <QMap>
#include <QSet>
#include <QTimer>
#include <polkitqt1-authority.h>
#include <polkitqt1-subject.h>
#include <polkitqt1-agent-listener.h>
#include <polkitqt1-agent-session.h>

#include "nfc-detector.h"

/*
 * Authentication state machine
 *
 * Inspired by GDM's GdmSessionWorkerState pattern
 * See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session-worker.h
 * SPDX-License-Identifier: GPL-2.0-or-later (for GDM reference pattern)
 */
enum class AuthenticationState {
    IDLE = 0,                    // No authentication in progress
    INITIATED,                   // Authentication request received, session created
    TRYING_FIDO,                 // Auto-attempting FIDO/U2F authentication
    FIDO_FAILED,                 // FIDO attempt failed, preparing fallback
    WAITING_FOR_PASSWORD,        // Password prompt shown, waiting for user input
    AUTHENTICATING,              // PAM is processing credentials
    AUTHENTICATION_FAILED,       // PAM rejected credentials (recoverable)
    MAX_RETRIES_EXCEEDED,        // Too many failed attempts (terminal)
    COMPLETED,                   // Authentication succeeded
    CANCELLED,                   // User cancelled authentication
    ERROR                        // Unrecoverable error occurred
};

/*
 * Authentication method being attempted
 */
enum class AuthenticationMethod {
    NONE,
    FIDO,        // FIDO/U2F/NFC
    PASSWORD     // Password authentication
};

/*
 * Per-session state tracking
 *
 * GDM uses separate "conversations" per auth method. We track state per cookie
 * to support concurrent authentication requests.
 */
struct SessionState {
    AuthenticationState state = AuthenticationState::IDLE;
    AuthenticationMethod method = AuthenticationMethod::NONE;
    QString cookie;
    QString actionId;
    int retryCount = 0;
    bool nfcAttempted = false;

    // Polkit objects
    PolkitQt1::Agent::AsyncResult *result = nullptr;
    PolkitQt1::Agent::Session *session = nullptr;

    // FIDO timeout timer
    QTimer *fidoTimeoutTimer = nullptr;
};

class PolkitWrapper : public PolkitQt1::Agent::Listener
{
    Q_OBJECT
    Q_ENUM(AuthenticationState)
    Q_ENUM(AuthenticationMethod)

public:
    explicit PolkitWrapper(INfcDetector *nfcDetector = nullptr, QObject *parent = nullptr);
    ~PolkitWrapper();

    // Register/unregister as polkit agent
    bool registerAgent();
    void unregisterAgent();

    // State inspection (for testing and debugging)
    AuthenticationState authenticationState(const QString &cookie = QString()) const;
    AuthenticationMethod authenticationMethod(const QString &cookie) const;
    bool hasActiveSessions() const;
    int sessionRetryCount(const QString &cookie) const;

#ifdef BUILD_TESTING
    /*
     * Test-only method to trigger authentication
     *
     * In production, initiateAuthentication() is called by polkit daemon via D-Bus.
     * For testing, we expose this to allow triggering authentication flows.
     */
    void testTriggerAuthentication(const QString &actionId,
                                   const QString &message,
                                   const QString &iconName,
                                   const QString &cookie);

    /*
     * Test-only method to manually complete a PAM session
     *
     * This allows testing retry logic without requiring real polkit-agent-helper-1.
     * Manually triggers the completed signal to simulate PAM finishing.
     *
     * @param cookie The session cookie
     * @param success Whether authentication succeeded
     */
    void testCompleteSession(const QString &cookie, bool success);
#endif

public slots:
    void checkAuthorization(const QString &actionId, const QString &details = QString());
    void cancelAuthorization();
    void submitAuthenticationResponse(const QString &cookie, const QString &response);

signals:
    // Signal to show auth dialog in quickshell
    void showAuthDialog(const QString &actionId, const QString &message, const QString &iconName, const QString &cookie);

    // Signal when authorization completes
    void authorizationResult(bool authorized, const QString &actionId);

    // Signal for errors
    void authorizationError(const QString &error);

    // Signal for password requests (FIDO fallback)
    void showPasswordRequest(const QString &actionId, const QString &request, bool echo, const QString &cookie);

    // State machine signals (for UI feedback)
    void authenticationStateChanged(const QString &cookie, AuthenticationState state);
    void authenticationMethodChanged(const QString &cookie, AuthenticationMethod method);
    void authenticationMethodFailed(const QString &cookie, AuthenticationMethod method, const QString &reason);

    /*
     * Comprehensive error signal (Option C: Defaults + Overrides)
     *
     * Provides both a default user-friendly message and technical details.
     * QML can use the default message or provide custom messages based on state/method.
     *
     * Example QML usage:
     *   onAuthenticationError: function(cookie, state, method, defaultMsg, details) {
     *       // Use custom message if you want:
     *       if (state === AuthenticationState.MAX_RETRIES_EXCEEDED) {
     *           showError("Slow down there, cowboy!");
     *       } else {
     *           showError(defaultMsg);  // Use default
     *       }
     *   }
     */
    void authenticationError(const QString &cookie,
                            AuthenticationState state,
                            AuthenticationMethod method,
                            const QString &defaultMessage,
                            const QString &technicalDetails);

protected:
    // PolkitQt1::Agent::Listener interface
    void initiateAuthentication(const QString &actionId,
                               const QString &message,
                               const QString &iconName,
                               const PolkitQt1::Details &details,
                               const QString &cookie,
                               const PolkitQt1::Identity::List &identities,
                               PolkitQt1::Agent::AsyncResult *result) override;

    bool initiateAuthenticationFinish() override;
    void cancelAuthentication() override;

private slots:
    void onCheckAuthorizationFinished(PolkitQt1::Authority::Result result);

private:
    PolkitQt1::Authority *m_authority;
    QString m_currentActionId;

    // Unified session state tracking (replaces three separate maps)
    QMap<QString, SessionState> m_sessions;

    // NFC reader detection (dependency injection)
    INfcDetector *m_nfcDetector;
    bool m_ownDetector;  // True if we created the detector (need to delete)

    // Message transformation for user-friendly text
    QString transformAuthMessage(const QString &actionId, const QString &message, const PolkitQt1::Details &details);

    // State machine helpers
    void setState(const QString &cookie, AuthenticationState newState);
    void setMethod(const QString &cookie, AuthenticationMethod method);
    void cleanupSession(const QString &cookie);
    SessionState* getSession(const QString &cookie);
    const SessionState* getSession(const QString &cookie) const;
    QString stateToString(AuthenticationState state) const;
    QString methodToString(AuthenticationMethod method) const;

    // FIDO timeout handling
    void startFidoTimeout(const QString &cookie);
    void cancelFidoTimeout(const QString &cookie);
    void onFidoTimeout(const QString &cookie);

    // Error message generation (inspired by GDM's get_friendly_error_message)
    // See: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session-worker.c:846
    QString getDefaultErrorMessage(AuthenticationState state, AuthenticationMethod method) const;

    // Configuration
    static constexpr int FIDO_TIMEOUT_MS = 15000;  // 15 seconds
    static constexpr int MAX_AUTH_RETRIES = 3;     // Max failed attempts before lockout
};