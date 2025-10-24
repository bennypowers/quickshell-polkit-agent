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

#include "nfc-detector.h"
#include "logging.h"
#include <QProcess>
#include <QStringList>

bool UsbNfcDetector::isPresent()
{
    QProcess lsusb;
    lsusb.start("lsusb");

    // Check if process started successfully
    if (lsusb.state() == QProcess::NotRunning) {
        qCDebug(polkitAgent) << "Failed to start lsusb - command not available";
        return false;
    }

    // Timeout increased to handle systems with many USB devices or under load
    if (!lsusb.waitForFinished(500)) {
        qCDebug(polkitAgent) << "lsusb command timed out:" << lsusb.errorString();
        lsusb.kill();
        return false;
    }

    // Check for process errors after completion
    if (lsusb.exitStatus() != QProcess::NormalExit || lsusb.exitCode() != 0) {
        qCDebug(polkitAgent) << "lsusb command failed:" << lsusb.errorString();
        return false;
    }

    QString output = QString::fromUtf8(lsusb.readAllStandardOutput()).toLower();

    // Known NFC/FIDO device identifiers
    // Add new device vendor IDs or product names here as needed
    static const QStringList knownDevices = {
        "072f:",     // ACS (ACR122U and other readers)
        "acr122",    // ACR122U by name
        "1050:",     // Yubico vendor ID
        "yubikey",   // YubiKey by name
        // Add more devices here as needed
    };

    // Check if any known device is present
    for (const QString& device : knownDevices) {
        if (output.contains(device)) {
            qCDebug(polkitAgent) << "NFC/FIDO device detected:" << device;
            return true;
        }
    }

    qCDebug(polkitAgent) << "No NFC/FIDO reader detected";
    return false;
}
