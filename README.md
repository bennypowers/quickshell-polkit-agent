# Quickshell Polkit Agent

> [!CAUTION]
> **SECURITY-CRITICAL SOFTWARE**: This polkit agent handles system authentication.
> Use at your own risk. Review the code before installation. See LICENSE for terms.
> The author is not responsible for any security vulnerabilities or system damage.

A custom polkit authentication agent that provides beautiful, custom authentication dialogs through quickshell instead of the default system dialogs.

## Features

- **🔐 FIDO2/WebAuthn Support**: Full support for FIDO security keys (YubiKey, etc.) with automatic detection
- **🔑 Password Authentication**: Traditional password authentication with fallback support
- **✨ Custom Authentication UI**: Beautiful custom-themed dialogs instead of system defaults
- **👤 Real User Data**: Quickshell UI integrates with AccountsService for user avatars and information
- **🔒 Secure Authentication**: Uses PolkitQt1 sessions for authentication (PAM handled internally by polkit)
- **📡 IPC Communication**: Unix domain socket communication between agent and quickshell
- **🔧 System Integration**: Registers as the system polkit agent for all authentication requests
- **🔄 Reliable Operation**: Stable authentication flow with proper session management

## Installation

### Building from Source

```bash
# Install dependencies (example for Gentoo)
emerge -av qt6-base qt6-network polkit-qt

# Build
cmake -B build
cmake --build build

# Install
sudo cmake --install build
```

For distribution-specific packaging, see [PACKAGING.md](PACKAGING.md).

### Systemd Service

The polkit agent runs as a user systemd service:

```bash
# Enable and start the service
systemctl --user enable quickshell-polkit-agent.service
systemctl --user start quickshell-polkit-agent.service

# Check status
systemctl --user status quickshell-polkit-agent.service
```

### Quickshell Configuration

Copy the provided `PolkitAgent.qml` component to your quickshell configuration directory (typically `~/.config/quickshell/`).

**Basic integration in your shell.qml:**
```qml
import QtQuick
import Quickshell

ShellRoot {
    PolkitAgent {
        id: polkitAgent
        
        onShowAuthDialog: function(actionId, message, iconName, cookie) {
            // Handle authentication dialog display
            console.log("Authentication required for:", actionId)
            // Implement your custom UI here
        }
        
        onAuthorizationResult: function(authorized, actionId) {
            console.log("Result:", authorized ? "GRANTED" : "DENIED")
            // Handle result (close dialog, show status, etc.)
        }
        
        onAuthorizationError: function(error) {
            console.log("Error:", error)
            // Handle error display
        }
    }
}
```

**Required component:**
- `PolkitAgent.qml` - Main component for polkit communication (provided in `quickshell/` and `examples/`)

## Usage

Once installed and configured, the custom authentication dialogs will automatically appear for any polkit-enabled application:

```bash
# These commands will show custom quickshell dialogs
pkexec ls
pkexec systemctl restart some-service
# Any application requesting elevated privileges
```

### Authentication Methods

**FIDO2/WebAuthn Authentication:**
- Automatically detects FIDO security keys (YubiKey, Nitrokey, etc.)
- Shows "Touch your security key" prompt
- Handles FIDO timeout with password fallback
- Supports retry attempts

**Password Authentication:**
- Traditional password entry for systems without FIDO keys
- Secure PAM integration via polkit
- Real-time validation and error handling

**Smart Fallback:**
- FIDO authentication with password fallback on timeout
- "Try Security Key Again" option
- Seamless switching between authentication methods

### Testing the Implementation

Test the polkit authentication with any elevated command:

```bash
# Test with pkexec
pkexec echo "Authentication successful"

# Test with systemctl
pkexec systemctl status some-service
```

### API Usage

The authentication happens automatically when any application requests polkit authorization. The UI components handle the display and user interaction.

**Key signals from PolkitAgent:**
- `showAuthDialog(actionId, message, iconName, cookie)` - Authentication required
- `authorizationResult(authorized, actionId)` - Result received  
- `authorizationError(error)` - Error occurred
- `connected()` - Connected to agent
- `disconnected()` - Disconnected from agent

## Configuration

### Socket Path

The polkit agent creates a Unix domain socket at:
```
/run/user/$(id -u)/quickshell-polkit
```

### Security Considerations

> [!WARNING]
> **CRITICAL**: This agent handles system authentication. Improper configuration
> or bugs could compromise system security.

**Security measures implemented:**
- Unix domain sockets with user-only permissions
- Minimal systemd service configuration
- PolkitQt1 handles actual authentication (no direct PAM usage)
- Agent runs as user service (no elevated privileges)

**Security responsibilities:**
- Audit all code before deployment
- Ensure quickshell configuration is secure
- Monitor logs for authentication anomalies
- Keep dependencies updated
- Test thoroughly in isolated environments first

## Development

### Building
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

### Testing
```bash
# Start agent manually
./quickshell-polkit-agent

# In another terminal, trigger auth
pkexec ls
```

### Check Service Status
```bash
systemctl --user status quickshell-polkit-agent.service
journalctl --user -u quickshell-polkit-agent.service -f
```

### Test Authentication
```bash
# Should show custom dialog
pkexec echo "test"
```

### Socket Connection Issues
```bash
# Check if socket exists
ls -la /run/user/$(id -u)/quickshell-polkit

# Check quickshell logs
journalctl --user -f | grep quickshell
```

### Project Structure

```
quickshell-polkit-agent/
├── src/                          # C++ source code
│   ├── main.cpp                  # Main application entry point
│   ├── polkit-wrapper.{cpp,h}    # PolkitQt1 wrapper
│   └── ipc-server.{cpp,h}        # Unix socket IPC server
├── quickshell/                   # Quickshell components
│   └── PolkitAgent.qml          # Main polkit component
├── examples/                     # Example implementations
│   ├── example-shell.qml        # Complete test shell
│   └── PolkitAgent.qml          # Component copy for reference
├── packaging/                    # Distribution packaging
│   ├── systemd/                 # Systemd service files
│   └── gentoo/                  # Gentoo ebuilds
└── CMakeLists.txt               # Build configuration
```

### Dependencies

- Qt6 Core and Network
- polkit-qt6-core-1
- polkit-qt6-agent-1
- quickshell (for UI components)
- socat (for Unix socket communication)

