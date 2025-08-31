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
#include <QFileSystemWatcher>
#include <QTimer>
#include <QJsonObject>

class PolkitWrapper;

class FileIPC : public QObject
{
    Q_OBJECT

public:
    explicit FileIPC(PolkitWrapper *polkitWrapper, QObject *parent = nullptr);
    ~FileIPC();

    bool initialize();

private slots:
    void onResponseFileChanged();
    void checkForResponses();
    
    // Slots for polkit wrapper signals
    void onShowAuthDialog(const QString &actionId, const QString &message, const QString &iconName, const QString &cookie);
    void onAuthorizationResult(bool authorized, const QString &actionId);
    void onAuthorizationError(const QString &error);

private:
    void writeRequest(const QJsonObject &message);
    void handleResponse(const QJsonObject &message);

    QString m_requestFilePath;
    QString m_responseFilePath;
    QFileSystemWatcher *m_watcher;
    QTimer *m_pollTimer;
    PolkitWrapper *m_polkitWrapper;
};