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

### API Reference

#### Core Signals

**Authentication Flow:**
- `showAuthDialog(actionId, message, iconName, cookie)` - Authentication required, show UI
- `showPasswordRequest(actionId, request, echo, cookie)` - PAM requests input (password or FIDO prompt)
- `authorizationResult(authorized, actionId)` - Final result received
- `authorizationError(error)` - General/authority errors (used by IPC protocol)

**Connection Status:**
- `connected()` - Connected to agent backend
- `disconnected()` - Disconnected from agent backend

#### State Machine Signals (New)

**State Tracking:**
- `authenticationStateChanged(cookie, AuthenticationState)` - Session state transition
- `authenticationMethodChanged(cookie, AuthenticationMethod)` - Auth method changed
- `authenticationMethodFailed(cookie, method, reason)` - Method failed

**Comprehensive Error Handling:**
```qml
onAuthenticationError: function(cookie, state, method, defaultMessage, technicalDetails) {
    // state: AuthenticationState enum
    // method: AuthenticationMethod enum
    // defaultMessage: User-friendly message from C++
    // technicalDetails: Technical error info

    // Option 1: Use default message
    showError(defaultMessage)

    // Option 2: Custom message based on state
    if (state === AuthenticationState.MAX_RETRIES_EXCEEDED) {
        showError("Too many attempts! Take a break.")
    } else {
        showError(defaultMessage)
    }
}
```

#### Authentication States

```qml
enum AuthenticationState {
    IDLE,                     // No authentication in progress
    INITIATED,                // Request received, session created
    WAITING_FOR_PASSWORD,     // Password prompt shown
    AUTHENTICATING,           // PAM processing credentials
    AUTHENTICATION_FAILED,    // Failed (recoverable - can retry)
    MAX_RETRIES_EXCEEDED,     // Too many attempts (terminal)
    COMPLETED,                // Authentication succeeded
    CANCELLED,                // User cancelled
    ERROR                     // Unrecoverable error
}
```

**Note:** FIDO authentication is handled entirely by PAM (via `pam_u2f` if configured). The agent responds reactively to PAM prompts without managing FIDO flow directly.

##### UI State Mapping
- `WAITING_FOR_PASSWORD` → Show password input field
- `AUTHENTICATING` → Show "Checking credentials..." with spinner
- `AUTHENTICATION_FAILED` → Show error, keep dialog open for retry
- `MAX_RETRIES_EXCEEDED` → Show error, close dialog (no retry)

#### Authentication Methods

```qml
enum AuthenticationMethod {
    NONE,      // No method selected yet
    FIDO,      // FIDO/U2F/NFC security key
    PASSWORD   // Password authentication
}
```

#### State Inspection Methods

```qml
// Check current state for a session
polkitAgent.authenticationState(cookie)  // Returns AuthenticationState
polkitAgent.authenticationState()        // Global state (first active session)

// Check authentication method
polkitAgent.authenticationMethod(cookie) // Returns AuthenticationMethod

// Check if any sessions active
polkitAgent.hasActiveSessions()          // Returns bool

// Check retry count
polkitAgent.sessionRetryCount(cookie)    // Returns int (0-3)
```

#### Error Messages

The agent provides default user-friendly error messages based on state and method:

| State                   | Method     | Default Message                                                                        |
| ----------------------- | ---------- | -------------------------------------------------------------------------------------- |
| `MAX_RETRIES_EXCEEDED`  | `PASSWORD` | "You reached the maximum password authentication attempts. Please try another method." |
| `AUTHENTICATION_FAILED` | `PASSWORD` | "Incorrect password. Please try again."                                                |
| `ERROR`                 | Any        | "An error occurred during authentication. Please try again."                           |

**Note on FIDO:** FIDO authentication errors are handled by PAM. The agent displays whatever prompt or error PAM provides.

**Custom Error Messages**
QML can use default messages or override with custom text based on state/method combination.

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

### Testing

**Quick local tests:**
```bash
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON
make -j$(nproc)
make test
```

**Comprehensive testing (all tests in container):**
```bash
make test-container
```

**Test suites:**
- **Unit Tests** - MessageValidator, SecurityManager, LocalSocket, performance
- **Integration Tests** - Authentication state machine, FIDO flows (container-only)
- **E2E Tests** - Real polkit daemon integration (container-only)

The simplified approach:
- `make test` - Fast local unit tests (safe for development)
- `make test-container` - ALL tests in isolated Podman container

### Troubleshooting
```bash
# Test authentication
pkexec echo "test"

# Check service status
systemctl --user status quickshell-polkit-agent.service
journalctl --user -u quickshell-polkit-agent.service -f

# Debug socket issues
ls -la /run/user/$(id -u)/quickshell-polkit
journalctl --user -f | grep quickshell

# Enable debug logging
export QT_LOGGING_RULES="polkit.agent.debug=true;polkit.sensitive.debug=false"
```

### Project Structure

```
quickshell-polkit-agent/
├── src/                          # C++ source code
│   ├── main.cpp                  # Main application entry point
│   ├── polkit-wrapper.{cpp,h}    # PolkitQt1 wrapper with state machine
│   ├── ipc-server.{cpp,h}        # Unix socket IPC server
│   ├── security.{cpp,h}          # Security validation
│   ├── message-validator.{cpp,h} # Message validation
│   └── logging.{cpp,h}           # Logging categories
├── tests/                        # Test suite
│   ├── test-authentication-state-integration.cpp  # State machine tests
│   ├── test-localsocket-validation.cpp            # IPC tests
│   ├── security/                 # Python security tests
│   ├── e2e/                      # Podman E2E tests
│   └── pam/                      # PAM wrapper configs
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

