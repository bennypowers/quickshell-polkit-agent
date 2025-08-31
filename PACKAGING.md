# Packaging Guide

This document provides packaging information for distribution maintainers and advanced users.

## Dependencies

### Runtime Dependencies
- Qt6 Core (>= 6.0)
- Qt6 Network (>= 6.0) 
- polkit-qt6-core-1 (>= 0.114.0)
- polkit-qt6-agent-1 (>= 0.114.0)
- polkit (>= 0.120)
- systemd (for user service)

### Build Dependencies
- CMake (>= 3.16)
- Qt6 Development headers
- polkit-qt6 development headers
- C++17 compiler (GCC 9+ or Clang 10+)

### Optional Dependencies
- quickshell (for UI components)
- FIDO2/libfido2 (for hardware key support - handled by polkit)

## Directory Structure

- `packaging/systemd/` - Contains systemd service files
- `packaging/gentoo/` - Gentoo ebuilds and metadata
- `src/` - C++ source code
- `CMakeLists.txt` - Build configuration

## Distribution Packaging

I've tested this on gentoo, YMMV though. 

### Gentoo

Example ebuild structure:

```bash
# Install dependencies
emerge -av dev-qt/qtcore:6 dev-qt/qtnetwork:6 dev-libs/polkit-qt

# Ebuild example
EAPI=8
inherit cmake

DESCRIPTION="Custom polkit agent for quickshell"
DEPEND="
    dev-qt/qtcore:6
    dev-qt/qtnetwork:6  
    dev-libs/polkit-qt[qt6]
    sys-auth/polkit
"
RDEPEND="${DEPEND}"
```

To create a local overlay for testing:

```bash
# Create overlay directory
mkdir -p /var/db/repos/local

# Setup overlay metadata
echo 'masters = gentoo' > /var/db/repos/local/metadata/layout.conf
echo 'repo-name = local' >> /var/db/repos/local/metadata/layout.conf

# Create package directory
mkdir -p /var/db/repos/local/app-misc/quickshell-polkit-agent

# Copy ebuild files
cp packaging/gentoo/* /var/db/repos/local/app-misc/quickshell-polkit-agent/
```

### Arch Linux

```bash
# Example PKGBUILD structure
pkgname=quickshell-polkit-agent
pkgver=1.0.0
arch=('x86_64')
depends=('qt6-base' 'polkit-qt6' 'systemd')
makedepends=('cmake' 'gcc')
```

### Debian/Ubuntu

```bash
# Required packages
apt install qtbase6-dev libpolkit-qt6-1-dev cmake build-essential

# Package dependencies
Depends: libqt6core6, libqt6network6, libpolkit-qt6-1-1, polkit-1, systemd
Build-Depends: qtbase6-dev, libpolkit-qt6-1-dev, cmake
```

### Red Hat/Fedora

```bash
# Required packages  
dnf install qt6-qtbase-devel polkit-qt6-devel cmake gcc-c++

# Package dependencies
Requires: qt6-qtbase, polkit-qt6, polkit, systemd
BuildRequires: qt6-qtbase-devel, polkit-qt6-devel, cmake
```

### Other Distributions

Contributions for additional distribution packaging formats are welcome.

## Build Instructions

### Standard Build

```bash
# Configure build
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr

# Build
cmake --build build

# Install
sudo cmake --install build
```

### Build Options

- `CMAKE_BUILD_TYPE`: `Release`, `Debug`, or `RelWithDebInfo`
- `CMAKE_INSTALL_PREFIX`: Installation prefix (default: `/usr/local`)
- `SYSTEMD_USER_UNIT_DIR`: Systemd user unit directory (auto-detected)

### Installation Layout

Default installation paths:

| Component | Path |
|-----------|------|
| Binary | `${CMAKE_INSTALL_PREFIX}/libexec/quickshell-polkit-agent` |
| Systemd Service | `${SYSTEMD_USER_UNIT_DIR}/quickshell-polkit-agent.service` |
| License | `${CMAKE_INSTALL_PREFIX}/share/licenses/quickshell-polkit-agent/` |

## Post-Installation

### User Setup

After installation, users need to:

```bash
# Enable the service
systemctl --user enable quickshell-polkit-agent.service

# Start the service
systemctl --user start quickshell-polkit-agent.service
```

### Configuration

Users must configure their quickshell setup with the provided component:
- `PolkitAgent.qml` - Main polkit communication component

## Security Considerations

### Service Permissions

The systemd service is minimal and runs as a user service:
- No elevated privileges required
- User-only socket permissions in `/run/user/$(id -u)/`
- Automatic restart on failure

### File Permissions

Recommended file permissions:
- Binary: `755` (executable by all, writable by root)
- Service file: `644` (readable by all, writable by root)
- Socket directory: `700` (user-only access)

## Troubleshooting

### Common Issues

**Service fails to start:**
```bash
# Check service status
systemctl --user status quickshell-polkit-agent.service

# Check dependencies
ldd /usr/libexec/quickshell-polkit-agent
```

**Socket connection issues:**
```bash
# Verify socket exists
ls -la /run/user/$(id -u)/quickshell-polkit/

# Check polkit registration
pkexec echo test
```

**Permission errors:**
```bash
# Verify polkit installation
pkaction --version

# Check user session
loginctl show-user $(whoami)
```

### Debugging

Enable debug logging:
```bash
# View agent logs
journalctl --user -u quickshell-polkit-agent.service -f

# Test authentication manually
pkexec --disable-internal-agent echo test
```
