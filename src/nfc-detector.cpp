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

bool UsbNfcDetector::isPresent()
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
