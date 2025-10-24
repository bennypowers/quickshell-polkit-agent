# Unit Tests

This directory contains unit tests for security-critical components of quickshell-polkit-agent.

## Test Coverage

### MessageValidator Tests (`test-message-validator.cpp`)
- **Valid message validation**: Tests all supported message types with valid data
- **Invalid message rejection**: Tests validation of malformed, missing, or invalid fields
- **Security validation**: Tests length limits, type checking, and format validation
- **Edge cases**: Tests boundary conditions and security constraints

### Security Manager Tests (`test-security.cpp`)
- **HMAC authentication**: Tests message authentication code generation and verification
- **Message signing/verification**: Tests complete message authentication flow
- **Session timeout**: Tests session expiration logic
- **Timestamp validation**: Tests replay protection mechanisms
- **Audit logging**: Tests security event logging

### Simple Integration Tests (`test-simple-integration.cpp`)
- **Message validation integration**: Tests JSON parsing with message validation
- **Security integration**: Tests HMAC signing/verification with message validation
- **Socket communication**: Tests basic Unix socket communication and message exchange

### Authentication State Integration Tests (`test-authentication-state-integration.cpp`)
**Note: These tests run ONLY in the E2E container environment** (see `tests/e2e/README.md`)

- **Normal password authentication**: End-user password flow with PAM
- **FIDO authentication flows**: Auto-attempt, timeout, fallback to password
- **Authentication cancellation**: User cancels authentication mid-flow
- **Wrong password retry**: Retry logic and max retries enforcement
- **State machine transitions**: All authentication state transitions
- **Session lifecycle**: Session creation, cleanup, error recovery
- **Concurrent authentication**: Multiple simultaneous sessions
- **FIDO/Password race conditions**: User submits password while FIDO in progress

These tests require:
- `polkit-agent-helper-1` setuid root (security risk locally)
- PAM wrapper for mocking authentication
- `pam_fido_mock.so` for simulating FIDO devices

**Run via:** `./tests/e2e/run-podman-e2e.sh` (container environment only)

## Running Tests

### Quick Start

```bash
# Build with tests enabled
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
make

# Run local unit tests (fast, safe)
make test

# Run ALL tests in container (comprehensive, includes E2E and auth tests)
make test-container
```

### Local Unit Tests

Standard `make test` runs CTest locally - safe and fast for development:

```bash
cd build
make test
```

This runs:
- Message validation tests
- Security manager tests (HMAC, timestamps, etc.)
- Simple integration tests
- LocalSocket validation tests
- Performance/stress tests

**Individual test execution:**
```bash
cd build/tests
./test-message-validator
./test-security
./test-simple-integration
```

**Note:** Authentication state integration tests are excluded from local CTest. They require privileged operations and run only in containers.

### Container Tests (All Tests)

For comprehensive testing including authentication flows:

```bash
cd build
make test-container
```

This runs ALL tests in an isolated container with:
- Full polkit daemon + D-Bus
- PAM wrapper for authentication testing
- FIDO mock modules
- All E2E integration tests

See `tests/e2e/README.md` for details.

## Test Requirements

- Qt6 Test framework
- Qt6 Core and Network modules
- CMake 3.16+
- C++17 compiler

## Security Test Philosophy

These tests focus on security-critical components to ensure:

1. **Input validation** prevents malformed data from causing issues
2. **Authentication mechanisms** work correctly and can't be bypassed
3. **Session management** properly enforces timeouts and limits
4. **Rate limiting** protects against abuse
5. **Error handling** doesn't leak sensitive information

## Integration with CI/CD

These tests are designed to run in automated environments and will:
- Return non-zero exit codes on failure
- Provide detailed failure information
- Complete quickly (< 30 seconds total)
- Require no external dependencies beyond Qt6

## Adding New Tests

When adding new security features:

1. Add corresponding test cases to existing test files
2. Create new test files for new major components
3. Update CMakeLists.txt to include new test executables
4. Ensure tests cover both positive and negative cases
5. Test edge cases and security boundaries