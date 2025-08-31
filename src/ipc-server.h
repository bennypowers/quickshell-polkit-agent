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
#include <QLocalServer>
#include <QLocalSocket>
#include <QJsonObject>

class PolkitWrapper;

class IPCServer : public QObject
{
    Q_OBJECT

public:
    explicit IPCServer(PolkitWrapper *polkitWrapper, QObject *parent = nullptr);
    ~IPCServer();

    bool startServer(const QString &socketName = "quickshell-polkit");

private slots:
    void onNewConnection();
    void onClientDisconnected();
    void onClientDataReady();
    
    // Slots for polkit wrapper signals
    void onShowAuthDialog(const QString &actionId, const QString &message, const QString &iconName, const QString &cookie);
    void onAuthorizationResult(bool authorized, const QString &actionId);
    void onAuthorizationError(const QString &error);
    void onShowPasswordRequest(const QString &actionId, const QString &request, bool echo, const QString &cookie);

private:
    void sendMessageToClient(const QJsonObject &message);
    void handleClientMessage(const QJsonObject &message);

    QLocalServer *m_server;
    QLocalSocket *m_currentClient;
    PolkitWrapper *m_polkitWrapper;
};