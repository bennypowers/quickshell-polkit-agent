# Security Testing Documentation

This directory contains comprehensive security tests for the quickshell-polkit-agent to ensure robust protection against various attack vectors.

## Overview

The security test suite validates:

1. **IPC Socket Fuzzing** - Protection against malformed and oversized JSON messages
2. **Permission Manipulation** - Socket directory security and symlink protection  
3. **Replay/Race Conditions** - Authentication cookie and session security
4. **Rate Limiting** - DoS protection and connection abuse prevention
5. **Audit Logging** - Log rotation, flooding resistance, and integrity
6. **UI Confusion** - Protection against misleading dialogs and fake responses

## Test Structure

```
tests/security/
├── run_security_tests.py       # Main test runner
├── fuzz_ipc_socket.py          # IPC socket fuzzing tests
├── test_permissions.py         # Permission and symlink security
├── test_replay_attacks.py      # Replay attack and race condition tests
├── test_rate_limiting.py       # Rate limiting and timeout tests
├── test_audit_logging.py       # Audit log security tests
├── test_ui_confusion.py        # UI confusion attack tests
└── reports/                    # Generated test reports (JSON)
```

## Running Security Tests

### Quick Start

Run all security tests:
```bash
python3 tests/security/run_security_tests.py
```

### Individual Tests

Run specific test categories:
```bash
# IPC Socket Fuzzing
python3 tests/security/fuzz_ipc_socket.py

# Permission Security
python3 tests/security/test_permissions.py

# Replay Attacks
python3 tests/security/test_replay_attacks.py

# Rate Limiting
python3 tests/security/test_rate_limiting.py

# Audit Logging
python3 tests/security/test_audit_logging.py

# UI Confusion
python3 tests/security/test_ui_confusion.py
```

### Using CMake/CTest

Security tests are integrated with the CMake build system:
```bash
# Build and run all tests including security
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON
make
ctest --output-on-failure

# Run only security tests
ctest --tests-regex "Security|Fuzz|Permission|Replay|RateLimit|Audit|UIConfusion"
```

## Test Details

### 1. IPC Socket Fuzzing (`fuzz_ipc_socket.py`)

Tests the IPC socket against various malformed inputs:

- **Malformed JSON**: Invalid syntax, missing fields, control characters
- **Oversized Messages**: Large strings, deep nesting, many fields  
- **Random Payloads**: Fuzzing with random data structures
- **Protocol Violations**: Non-JSON data, HTTP requests, binary data

**Expected Results**: All malformed inputs should be rejected gracefully without crashes.

### 2. Permission Security (`test_permissions.py`)

Validates file system security:

- **Directory Permissions**: Ensures socket directories are not world-writable
- **Symlink Protection**: Detects symlink attacks to sensitive locations
- **File Ownership**: Validates correct file ownership and permissions
- **Race Conditions**: Tests for permission check race conditions

**Expected Results**: Security violations are detected and prevented.

### 3. Replay Attack Protection (`test_replay_attacks.py`)

Tests authentication security:

- **Cookie Replay**: Validates authentication cookies cannot be replayed
- **Session Expiry**: Ensures session timeouts are properly enforced
- **Timestamp Validation**: Protects against timestamp manipulation
- **HMAC Protection**: Validates message authentication codes
- **Concurrent Auth**: Tests race conditions in authentication

**Expected Results**: Replay attacks are blocked by HMAC and timestamp validation.

### 4. Rate Limiting (`test_rate_limiting.py`)

Validates DoS protection mechanisms:

- **Message Rate Limits**: Tests enforcement of message rate limits
- **Connection Timeouts**: Validates connection timeout enforcement
- **Concurrent Connections**: Tests limits on simultaneous connections
- **Slowloris Protection**: Tests against slow HTTP attack variants

**Expected Results**: Rate limits are enforced and abusive connections are terminated.

### 5. Audit Logging (`test_audit_logging.py`)

Tests logging security and integrity:

- **Log Rotation**: Validates log rotation under high load
- **Attack Logging**: Ensures security events are properly logged
- **Concurrent Access**: Tests log integrity under concurrent writes
- **Flood Resistance**: Tests resistance to log flooding attacks
- **Tampering Detection**: Basic log integrity validation

**Expected Results**: All security events are logged with proper rotation and integrity.

### 6. UI Confusion (`test_ui_confusion.py`)

Protects against UI-based attacks:

- **Malicious Content**: XSS, HTML injection, script content detection
- **Fake Responses**: Validation of agent response authenticity  
- **Dialog Spoofing**: Detection of fake system/application dialogs
- **Input Validation**: UI input sanitization and validation
- **Icon Security**: Protection against malicious icons and branding

**Expected Results**: UI attacks are detected and malicious content is blocked.

## CI/CD Integration

The security tests are integrated into GitHub Actions workflows:

- **Automated Testing**: Runs on every push and pull request
- **Scheduled Scans**: Daily security test execution
- **Failure Conditions**: Blocks merges if security tests fail
- **Report Generation**: Detailed JSON reports for analysis

See `.github/workflows/security-testing.yml` for CI configuration.

## Test Reports

All tests generate detailed JSON reports in `tests/security/reports/`:

- `security_test_summary.json` - Overall test suite results
- `fuzz_ipc_socket_report.json` - Fuzzing test details
- `permission_security_report.json` - Permission test results
- `replay_attack_report.json` - Replay attack test results  
- `rate_limiting_report.json` - Rate limiting test results
- `audit_log_report.json` - Audit logging test results
- `ui_confusion_report.json` - UI confusion test results

## Security Test Philosophy

These tests follow several key principles:

1. **Defense in Depth**: Multiple layers of security validation
2. **Fail Secure**: Tests ensure failures don't compromise security
3. **Real Attack Scenarios**: Based on actual attack patterns
4. **Comprehensive Coverage**: Tests cover all security-critical components
5. **CI/CD Integration**: Automated testing prevents regressions

## Adding New Security Tests

When adding new security features:

1. Add corresponding test cases to existing test files
2. Create new test files for major new security components
3. Update this documentation with test descriptions
4. Ensure tests cover both positive and negative cases
5. Add tests to CI/CD pipeline in `.github/workflows/security-testing.yml`

## Security Test Requirements

- Python 3.6+
- No external dependencies beyond Python standard library
- Tests should complete in under 5 minutes total
- All tests must be runnable without a live polkit agent
- Tests should generate detailed reports for analysis

## Known Limitations

- Some tests simulate attacks rather than testing against live systems
- Socket-based tests skip when agent is not running (CI environment)
- Permission tests create temporary files and directories
- Rate limiting tests use simulated load rather than real traffic

## Security Considerations

These tests themselves are designed with security in mind:

- Temporary files are properly cleaned up
- No sensitive data is written to logs
- Tests don't modify system-wide configurations
- All test data is generated, not sourced externally