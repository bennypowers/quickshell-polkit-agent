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

## References

- pam_wrapper docs: https://cwrap.org/pam_wrapper.html
- PAM config format: `man pam.conf`
