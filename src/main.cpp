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

#include <QCoreApplication>
#include <QDebug>
#include <signal.h>

#include "polkit-wrapper.h"
#include "ipc-server.h"
#include "security.h"

void signalHandler(int signal)
{
    qDebug() << "Received signal" << signal << "- shutting down gracefully";
    QCoreApplication::quit();
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("quickshell-polkit-agent");
    app.setApplicationVersion("1.0.0");
    
    // Handle signals gracefully
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    qDebug() << "Starting Quickshell Polkit Agent...";
    
    // Initialize security manager
    SecurityManager::initialize();
    
    // Create polkit wrapper
    PolkitWrapper polkitWrapper;
    
    // Register as polkit agent
    if (!polkitWrapper.registerAgent()) {
        qCritical() << "Failed to register as polkit agent - exiting";
        return 1;
    }
    
    // Create and start IPC server
    IPCServer server(&polkitWrapper);
    if (!server.startServer()) {
        qCritical() << "Failed to start IPC server - exiting";
        return 1;
    }
    
    qDebug() << "Quickshell Polkit Agent ready - registered as system polkit agent";
    
    return app.exec();
}