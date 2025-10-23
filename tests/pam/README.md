# PAM Mock Configuration for Testing

This directory contains mock PAM configurations used by libpam-wrapper for testing.

## Overview

We use [pam_wrapper](https://cwrap.org/pam_wrapper.html) to mock PAM authentication
without affecting the real system or risking account lockouts.

## How It Works

1. `pam_wrapper` intercepts PAM calls via `LD_PRELOAD`
2. Uses mock PAM configuration files from this directory
3. Returns success/failure based on test configuration
4. No real authentication occurs

## PAM Configurations

### Polkit Agent Service (used by PolkitQt1::Agent::Session)

- `polkit-1` - Default polkit service (permits all - for basic testing)
- `polkit-1-fail` - Polkit service that always fails

### Test Services

- `polkit-test-success` - Always succeeds (for testing happy path)
- `polkit-test-fail` - Always fails (for testing error handling)
- `polkit-test-fido` - Simulates FIDO/U2F authentication
- `polkit-test-password` - Simulates password authentication

## Environment Variables

Tests set these variables to use pam_wrapper:

```bash
PAM_WRAPPER=1
PAM_WRAPPER_SERVICE_DIR=/path/to/this/directory
LD_PRELOAD=libpam_wrapper.so
```

## Usage Example

```bash
# Set up pam_wrapper
export PAM_WRAPPER=1
export PAM_WRAPPER_SERVICE_DIR="$PWD/tests/pam"
export LD_PRELOAD=$(ldconfig -p | grep libpam_wrapper | awk '{print $4}' | head -1)

# Run tests
cd build
./tests/test-authentication-state-integration
```

## Testing Different Scenarios

To test specific failure scenarios, you can:

1. **Symlink different configs to `polkit-1`**:
   ```bash
   cd tests/pam
   ln -sf polkit-1-fail polkit-1
   ```

2. **Use environment variables** (if test supports):
   ```bash
   export PAM_SERVICE_NAME=polkit-1-fail
   ```

## Current Limitations

- **Password testing**: pam_permit/pam_deny don't simulate password prompts
  - Need pam_wrapper with custom modules or pwquality for realistic testing
- **FIDO testing**: No pam_u2f simulation in current configs
  - Would need mock FIDO device or pam_u2f test mode

## Future Improvements

- [ ] Add pam_unix simulation for password retries
- [ ] Add pam_u2f mock for FIDO flows
- [ ] Create custom PAM module for test control
- [ ] Support per-test PAM config selection

## References

- pam_wrapper docs: https://cwrap.org/pam_wrapper.html
- PAM config format: `man pam.conf`
- PolkitQt1 Agent docs: https://api.kde.org/polkit-qt-1/html/
