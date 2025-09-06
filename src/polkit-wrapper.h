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
#include <polkitqt1-authority.h>
#include <polkitqt1-subject.h>
#include <polkitqt1-agent-listener.h>
#include <polkitqt1-agent-session.h>

class PolkitWrapper : public PolkitQt1::Agent::Listener
{
    Q_OBJECT

public:
    explicit PolkitWrapper(QObject *parent = nullptr);
    ~PolkitWrapper();

    // Register/unregister as polkit agent
    bool registerAgent();
    void unregisterAgent();

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
    
    // Track active authentication sessions
    QMap<QString, PolkitQt1::Agent::AsyncResult*> m_activeSessions;
    QMap<QString, PolkitQt1::Agent::Session*> m_activePolkitSessions;
    
    // Message transformation for user-friendly text
    QString transformAuthMessage(const QString &actionId, const QString &message, const PolkitQt1::Details &details);
};