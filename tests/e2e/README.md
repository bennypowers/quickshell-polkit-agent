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
6. **Authentication State Integration** - Container-only tests for authentication flows:
   - Normal password authentication
   - FIDO/U2F authentication attempts and fallback
   - Authentication cancellation
   - Wrong password retry and max retries
   - State machine transitions
   - Session lifecycle management
   - Error recovery scenarios

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

## Container-Only Tests

Some tests are designed to run **only** in the E2E container environment, not locally via CTest:

### Authentication State Integration Tests

The `test-authentication-state-integration` binary contains comprehensive tests for authentication flows. These tests require:

1. **polkit-agent-helper-1 setuid root** - The polkit helper must be setuid to interact with PAM
2. **PAM wrapper** - Uses `pam_wrapper` to mock PAM authentication without affecting the host
3. **Mock FIDO module** - `pam_fido_mock.so` simulates FIDO/U2F devices for testing

**Why container-only?**
- Setting polkit-agent-helper-1 as setuid root locally is a security risk
- PAM configuration changes could interfere with system authentication
- The container provides isolated PAM and polkit environments

**Running these tests:**
```bash
# Tests run automatically as part of E2E suite
./tests/e2e/run-podman-e2e.sh

# Or manually in container
podman run -it --privileged --systemd=always quickshell-polkit-e2e /bin/bash
cd /workspace/build/tests
PAM_WRAPPER=1 PAM_WRAPPER_SERVICE_DIR=/workspace/tests/pam \
  LD_PRELOAD=/usr/lib64/libpam_wrapper.so \
  ./test-authentication-state-integration -v1
```

The tests gracefully skip when run locally (if polkit helper isn't properly configured) with a message indicating they should be run in the E2E container.

## Known Limitations

- Tests run as root inside container (required for polkit daemon)
- Authentication state integration tests only run in container (require setuid helper)
- Some tests may require systemd cgroups v2

## Future Improvements

- [ ] Test agent restart/recovery
- [ ] Add performance/stress tests in container environment
- [ ] Test with additional PAM module configurations
