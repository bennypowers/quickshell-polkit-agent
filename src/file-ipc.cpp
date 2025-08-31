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

#include "file-ipc.h"
#include "polkit-wrapper.h"
#include <QStandardPaths>
#include <QDir>
#include <QJsonDocument>
#include <QFile>
#include <QTextStream>
#include <QDebug>

FileIPC::FileIPC(PolkitWrapper *polkitWrapper, QObject *parent)
    : QObject(parent)
    , m_watcher(new QFileSystemWatcher(this))
    , m_pollTimer(new QTimer(this))
    , m_polkitWrapper(polkitWrapper)
{
    // Set up file paths
    QString runtimeDir = qEnvironmentVariable("XDG_RUNTIME_DIR");
    if (runtimeDir.isEmpty()) {
        runtimeDir = QString("/tmp");
        m_requestFilePath = QString("%1/quickshell-polkit-requests-%2").arg(runtimeDir).arg(getuid());
        m_responseFilePath = QString("%1/quickshell-polkit-responses-%2").arg(runtimeDir).arg(getuid());
    } else {
        m_requestFilePath = QString("%1/quickshell-polkit-requests").arg(runtimeDir);
        m_responseFilePath = QString("%1/quickshell-polkit-responses").arg(runtimeDir);
    }

    // Connect polkit wrapper signals
    if (m_polkitWrapper) {
        connect(m_polkitWrapper, &PolkitWrapper::showAuthDialog,
                this, &FileIPC::onShowAuthDialog);
        connect(m_polkitWrapper, &PolkitWrapper::authorizationResult,
                this, &FileIPC::onAuthorizationResult);
        connect(m_polkitWrapper, &PolkitWrapper::authorizationError,
                this, &FileIPC::onAuthorizationError);
    }

    // Set up response file monitoring
    connect(m_watcher, &QFileSystemWatcher::fileChanged,
            this, &FileIPC::onResponseFileChanged);
    
    // Fallback polling timer
    m_pollTimer->setInterval(1000); // Check every second
    connect(m_pollTimer, &QTimer::timeout, this, &FileIPC::checkForResponses);
}

FileIPC::~FileIPC()
{
    // Clean up files
    QFile::remove(m_requestFilePath);
    QFile::remove(m_responseFilePath);
}

bool FileIPC::initialize()
{
    qDebug() << "FileIPC: Initializing file-based IPC";
    qDebug() << "Request file:" << m_requestFilePath;
    qDebug() << "Response file:" << m_responseFilePath;

    // Create empty files
    QFile requestFile(m_requestFilePath);
    if (!requestFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "Failed to create request file:" << m_requestFilePath;
        return false;
    }
    requestFile.close();

    QFile responseFile(m_responseFilePath);
    if (!responseFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "Failed to create response file:" << m_responseFilePath;
        return false;
    }
    responseFile.close();

    // Add response file to watcher
    if (!m_watcher->addPath(m_responseFilePath)) {
        qWarning() << "Failed to watch response file, using polling";
        m_pollTimer->start();
    }

    qDebug() << "FileIPC: Ready for file-based communication";
    return true;
}

void FileIPC::onResponseFileChanged()
{
    checkForResponses();
}

void FileIPC::checkForResponses()
{
    QFile file(m_responseFilePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    QTextStream stream(&file);
    QString line;
    while (stream.readLineInto(&line)) {
        if (line.trimmed().isEmpty()) continue;
        
        QJsonParseError error;
        QJsonDocument doc = QJsonDocument::fromJson(line.toUtf8(), &error);
        if (error.error != QJsonParseError::NoError) {
            qWarning() << "Failed to parse response JSON:" << error.errorString();
            continue;
        }

        handleResponse(doc.object());
    }

    // Clear the response file after processing
    file.close();
    file.open(QIODevice::WriteOnly | QIODevice::Truncate);
    file.close();
}

void FileIPC::onShowAuthDialog(const QString &actionId, const QString &message, const QString &iconName, const QString &cookie)
{
    QJsonObject request;
    request["type"] = "show_auth_dialog";
    request["action_id"] = actionId;
    request["message"] = message;
    request["icon_name"] = iconName;
    request["cookie"] = cookie;

    qDebug() << "FileIPC: Writing auth dialog request";
    writeRequest(request);
}

void FileIPC::onAuthorizationResult(bool authorized, const QString &actionId)
{
    QJsonObject request;
    request["type"] = "authorization_result";
    request["authorized"] = authorized;
    request["action_id"] = actionId;

    writeRequest(request);
}

void FileIPC::onAuthorizationError(const QString &error)
{
    QJsonObject request;
    request["type"] = "authorization_error";
    request["error"] = error;

    writeRequest(request);
}

void FileIPC::writeRequest(const QJsonObject &message)
{
    QFile file(m_requestFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        qWarning() << "Failed to open request file for writing";
        return;
    }

    QJsonDocument doc(message);
    QTextStream stream(&file);
    stream << doc.toJson(QJsonDocument::Compact) << "\n";
    stream.flush();
    file.close();

    qDebug() << "FileIPC: Wrote request:" << doc.toJson(QJsonDocument::Compact);
}

void FileIPC::handleResponse(const QJsonObject &message)
{
    QString type = message["type"].toString();
    qDebug() << "FileIPC: Handling response:" << type;

    if (type == "submit_authentication") {
        QString cookie = message["cookie"].toString();
        QString response = message["response"].toString();
        
        if (m_polkitWrapper) {
            m_polkitWrapper->submitAuthenticationResponse(cookie, response);
        }
    }
}