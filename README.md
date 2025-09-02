# Quickshell Polkit Agent
<img width="2048" height="1153" alt="2025-09-01-232327_hyprshot" src="https://github.com/user-attachments/assets/9a808b04-88e0-4b23-b218-831c51788b12" />

> [!CAUTION]
> **SECURITY-CRITICAL SOFTWARE**: This polkit agent handles system authentication.
> Use at your own risk. Review the code before installation. See LICENSE for terms.
> The author is not responsible for any security vulnerabilities or system damage.

A custom polkit authentication agent that provides beautiful, custom authentication dialogs through quickshell instead of the default system dialogs.

## Features

- **FIDO2/WebAuthn Support**: Security keys (YubiKey, etc.) with automatic detection and password fallback
- **Custom Authentication UI**: Beautiful themed dialogs integrated with AccountsService for user data
- **Secure Communication**: Unix domain socket IPC with PolkitQt1 session management
- **System Integration**: Registers as the system polkit agent for all authentication requests

## Installation

### Gentoo 🐄

Install from the overlay:

```bash
# Add the overlay
eselect repository add bennypowers git https://github.com/bennypowers/gentoo-overlay

# Update portage
emerge --sync

# Install the package
emerge -av sys-auth/quickshell-polkit-agent
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

Once installed and configured, custom authentication dialogs will automatically appear for any polkit-enabled application (e.g., `pkexec ls`).

### API Signals

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

**Implemented security measures:**
- Unix domain sockets with user-only permissions
- PolkitQt1 handles authentication (no direct PAM usage)
- Agent runs as user service (no elevated privileges)

**Your responsibilities:**
- Audit code before deployment
- Secure quickshell configuration
- Monitor logs and keep dependencies updated

## Development

### Building
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

### Testing & Troubleshooting
```bash
# Test authentication
pkexec echo "test"

# Check service status
systemctl --user status quickshell-polkit-agent.service
journalctl --user -u quickshell-polkit-agent.service -f

# Debug socket issues
ls -la /run/user/$(id -u)/quickshell-polkit
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

