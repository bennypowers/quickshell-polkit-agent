# End-to-End Tests for quickshell-polkit-agent

This directory contains end-to-end (E2E) tests that verify the polkit agent works correctly with a real polkit daemon, D-Bus, and authorization requests.

## Overview

The E2E tests run in a Podman container with:
- **Real polkit daemon** (polkitd)
- **D-Bus session bus**
- **Test user** with password authentication
- **Test polkit actions** defined in policy files

These tests verify the agent's behavior in a real-world environment, unlike unit tests which mock dependencies.

## Test Coverage

The E2E tests verify:

1. **Agent Registration** - Agent successfully registers with polkit daemon
2. **Allowed Actions** - Actions that don't require authentication work correctly
3. **Denied Actions** - Actions configured to deny are properly rejected
4. **Concurrent Requests** - Multiple simultaneous authorization requests are handled
5. **Session Cleanup** - Agent properly cleans up sessions after completion

## Running E2E Tests

### Prerequisites

- Podman installed (or Docker with minor script modifications)
- On Fedora: `sudo dnf install podman`
- On Debian/Ubuntu: `sudo apt install podman`

### Quick Start

```bash
# From project root
./tests/e2e/run-podman-e2e.sh
```

This script will:
1. Build a container with all dependencies
2. Run the E2E tests inside the container
3. Report results

### Manual Container Run

If you want to run tests manually or debug:

```bash
# Build container
podman build -f tests/e2e/Containerfile.e2e -t quickshell-polkit-e2e .

# Run container interactively
podman run -it --privileged --systemd=always quickshell-polkit-e2e /bin/bash

# Inside container, run tests
/workspace/tests/e2e/run-e2e-tests.sh
```

## Test Files

- **Containerfile.e2e** - Container definition with polkit, D-Bus, and dependencies
- **run-podman-e2e.sh** - Host script to build container and run tests
- **run-e2e-tests.sh** - Test script that runs inside container
- **org.quickshell.polkit.test.policy** - Test polkit action definitions
- **polkit-test-rules.conf** - Polkit rules for test actions
- **test-results/** - Test output logs (gitignored)

## Test Actions

The E2E tests define several polkit actions:

- `org.quickshell.polkit.test.auth-required` - Requires authentication
- `org.quickshell.polkit.test.deny` - Always denied
- `org.quickshell.polkit.test.allow` - Allowed without authentication

## Debugging

### View Agent Logs

After running tests, check the agent log:

```bash
cat tests/e2e/test-results/agent.log
```

### Interactive Testing

Run the container interactively to manually test:

```bash
podman run -it --privileged --systemd=always quickshell-polkit-e2e /bin/bash

# Inside container:
# 1. Start D-Bus
eval $(dbus-launch --sh-syntax)

# 2. Start polkit daemon
sudo /usr/libexec/polkitd &

# 3. Start agent
/workspace/build/quickshell-polkit-agent &

# 4. Test with pkcheck
pkcheck --action-id org.quickshell.polkit.test.allow --process $$
```

## Integration with CI

The E2E tests can be integrated into CI workflows. See `.github/workflows/security-testing.yml` for an example.

## Known Limitations

- Tests run as root inside container (required for polkit daemon)
- Password authentication flows are difficult to test in headless environment
- FIDO/U2F authentication cannot be tested without real hardware
- Some tests may require systemd cgroups v2

## Future Improvements

- [ ] Add tests for password authentication with expect/pexpect
- [ ] Test error recovery scenarios
- [ ] Test agent restart/recovery
- [ ] Test with multiple concurrent sessions
- [ ] Add performance/stress tests
- [ ] Test FIDO authentication with virtual U2F device
