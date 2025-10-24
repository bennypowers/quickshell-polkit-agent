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

/**
 * Interface for NFC reader detection
 *
 * Allows dependency injection for testing FIDO authentication flows
 * without requiring actual hardware.
 */
class INfcDetector
{
public:
    virtual ~INfcDetector() = default;

    /**
     * Check if an NFC reader is present
     * @return true if NFC reader detected, false otherwise
     */
    virtual bool isPresent() = 0;
};

/**
 * Real NFC detector using USB device enumeration
 */
class UsbNfcDetector : public INfcDetector
{
public:
    bool isPresent() override;
};

/**
 * Mock NFC detector for testing
 * Only available when BUILD_TESTING is defined
 */
#ifdef BUILD_TESTING
class MockNfcDetector : public INfcDetector
{
public:
    explicit MockNfcDetector(bool present = false)
        : m_present(present) {}

    bool isPresent() override { return m_present; }

    void setPresent(bool present) { m_present = present; }

private:
    bool m_present;
};
#endif
