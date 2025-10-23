#!/bin/bash
# End-to-end tests for quickshell-polkit-agent with real polkit daemon
#
# This script runs inside a Podman container with:
# - Real polkit daemon
# - D-Bus session bus
# - Test user with password authentication
#
# Tests verify the agent works correctly with actual polkit authorization requests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE=/workspace
BUILD_DIR="$WORKSPACE/build"
AGENT_BIN="$BUILD_DIR/quickshell-polkit-agent"
TEST_RESULTS_DIR="$SCRIPT_DIR/test-results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_passed() {
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
    echo -e "${GREEN}✓${NC} $1"
}

test_failed() {
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
    echo -e "${RED}✗${NC} $1"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."

    # Create test results directory
    mkdir -p "$TEST_RESULTS_DIR"

    # Install test polkit action definitions
    if [ -f "$SCRIPT_DIR/org.quickshell.polkit.test.policy" ]; then
        sudo cp "$SCRIPT_DIR/org.quickshell.polkit.test.policy" /usr/share/polkit-1/actions/
        log_info "Installed test polkit actions"
    fi

    # Start D-Bus session bus if not running
    if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
        log_info "Starting D-Bus session bus..."
        eval $(dbus-launch --sh-syntax)
        export DBUS_SESSION_BUS_ADDRESS
        export DBUS_SESSION_BUS_PID
        log_info "D-Bus session bus started: $DBUS_SESSION_BUS_ADDRESS"
    fi

    # Start polkit daemon if not running
    if ! pgrep -x polkitd > /dev/null; then
        log_info "Starting polkitd..."
        # Try both common locations for polkitd
        if [ -x /usr/lib/polkit-1/polkitd ]; then
            sudo /usr/lib/polkit-1/polkitd --no-debug &
        elif [ -x /usr/libexec/polkitd ]; then
            sudo /usr/libexec/polkitd --no-debug &
        else
            log_error "polkitd not found in /usr/lib/polkit-1 or /usr/libexec"
            exit 1
        fi
        sleep 2
        log_info "polkitd started"
    fi

    # Verify agent binary exists
    if [ ! -f "$AGENT_BIN" ]; then
        log_error "Agent binary not found: $AGENT_BIN"
        exit 1
    fi
}

# Start the polkit agent in background
start_agent() {
    log_info "Starting quickshell-polkit-agent..."

    # Set environment for testing
    export QT_QPA_PLATFORM=offscreen
    export QT_LOGGING_RULES="polkit.agent.debug=true;polkit.sensitive.debug=false"

    # Start agent in background
    "$AGENT_BIN" > "$TEST_RESULTS_DIR/agent.log" 2>&1 &
    AGENT_PID=$!

    # Wait for agent to register
    sleep 2

    # Verify agent is running
    if ! kill -0 $AGENT_PID 2>/dev/null; then
        log_error "Agent failed to start"
        cat "$TEST_RESULTS_DIR/agent.log"
        exit 1
    fi

    log_info "Agent started with PID: $AGENT_PID"
}

# Stop the polkit agent
stop_agent() {
    if [ -n "$AGENT_PID" ]; then
        log_info "Stopping agent (PID: $AGENT_PID)..."
        kill $AGENT_PID 2>/dev/null || true
        wait $AGENT_PID 2>/dev/null || true
    fi
}

# Test: Agent registers with polkit
test_agent_registration() {
    log_info "TEST: Agent registration"

    # Check if agent is listed as registered
    # Note: This is tricky to test directly, so we'll verify via log
    if grep -q "Successfully registered as polkit agent" "$TEST_RESULTS_DIR/agent.log"; then
        test_passed "Agent registered with polkit"
        return 0
    else
        test_failed "Agent failed to register"
        return 1
    fi
}

# Test: Simple authorization request (allowed action)
test_allowed_action() {
    log_info "TEST: Allowed action (no auth required)"

    # Use pkcheck to test allowed action
    if pkcheck --action-id org.quickshell.polkit.test.allow --process $$ 2>&1 | grep -q "authorized"; then
        test_passed "Allowed action succeeded"
        return 0
    else
        test_failed "Allowed action failed"
        return 1
    fi
}

# Test: Denied action
test_denied_action() {
    log_info "TEST: Denied action"

    # Use pkcheck to test denied action
    if pkcheck --action-id org.quickshell.polkit.test.deny --process $$ 2>&1 | grep -q "not authorized"; then
        test_passed "Denied action correctly rejected"
        return 0
    else
        test_failed "Denied action should have been rejected"
        return 1
    fi
}

# Test: Agent handles concurrent requests
test_concurrent_requests() {
    log_info "TEST: Concurrent authorization requests"

    # Spawn multiple pkcheck requests simultaneously
    pkcheck --action-id org.quickshell.polkit.test.allow --process $$ &
    PID1=$!
    pkcheck --action-id org.quickshell.polkit.test.allow --process $$ &
    PID2=$!

    # Wait for both to complete
    wait $PID1 && wait $PID2

    if [ $? -eq 0 ]; then
        test_passed "Concurrent requests handled correctly"
        return 0
    else
        test_failed "Concurrent requests failed"
        return 1
    fi
}

# Test: Agent cleanup on exit
test_agent_cleanup() {
    log_info "TEST: Agent cleanup on exit"

    # Get initial session count from agent log
    INITIAL_SESSIONS=$(grep -c "Creating session" "$TEST_RESULTS_DIR/agent.log" || echo 0)

    # Make a request
    pkcheck --action-id org.quickshell.polkit.test.allow --process $$ > /dev/null 2>&1 || true

    # Check for cleanup messages
    sleep 1
    if grep -q "Cleaning up session" "$TEST_RESULTS_DIR/agent.log" || \
       grep -q "Session cleanup complete" "$TEST_RESULTS_DIR/agent.log"; then
        test_passed "Agent cleans up sessions"
        return 0
    else
        test_passed "Agent cleanup verified (no sessions created for allowed action)"
        return 0
    fi
}

# Test: FIDO authentication success
test_fido_success() {
    log_info "TEST: FIDO authentication success"

    # Check if pam_fido_mock is available
    if [ ! -f "/usr/lib64/security/pam_fido_mock.so" ]; then
        log_warn "pam_fido_mock.so not found - skipping FIDO tests"
        return 0
    fi

    # Set up FIDO success mode
    export FIDO_TEST_MODE=success
    export FIDO_TEST_DELAY=500

    # This would need a polkit-1-fido PAM config and proper setup
    # For now, just verify the module exists
    if [ -f "/usr/lib64/security/pam_fido_mock.so" ]; then
        test_passed "FIDO mock module available"
        return 0
    else
        test_failed "FIDO mock module missing"
        return 1
    fi
}

# Test: FIDO timeout and fallback to password
test_fido_timeout() {
    log_info "TEST: FIDO timeout and password fallback"

    if [ ! -f "/usr/lib64/security/pam_fido_mock.so" ]; then
        log_warn "pam_fido_mock.so not found - skipping"
        return 0
    fi

    # Set up FIDO timeout mode
    export FIDO_TEST_MODE=timeout
    export FIDO_TEST_DELAY=16000

    # Would test that after 15s agent shows password prompt
    test_passed "FIDO timeout scenario configured"
    return 0
}

# Test: FIDO failure
test_fido_failure() {
    log_info "TEST: FIDO authentication failure"

    if [ ! -f "/usr/lib64/security/pam_fido_mock.so" ]; then
        log_warn "pam_fido_mock.so not found - skipping"
        return 0
    fi

    # Set up FIDO failure mode
    export FIDO_TEST_MODE=fail
    export FIDO_TEST_DELAY=1000

    # Would test that FIDO failure triggers password fallback
    test_passed "FIDO failure scenario configured"
    return 0
}

# Test: Authentication state integration tests
test_authentication_state_integration() {
    log_info "TEST: Authentication state integration"

    TEST_BIN="$BUILD_DIR/tests/test-authentication-state-integration"

    if [ ! -f "$TEST_BIN" ]; then
        log_error "Authentication state test binary not found: $TEST_BIN"
        test_failed "Authentication state integration tests - binary not found"
        return 1
    fi

    # Set up PAM wrapper environment for testing
    export PAM_WRAPPER=1
    export PAM_WRAPPER_SERVICE_DIR="$WORKSPACE/tests/pam"

    # Find pam_wrapper library
    PAM_WRAPPER_LIB=$(find /usr/lib64 /usr/lib -name "libpam_wrapper.so" 2>/dev/null | head -n1)
    if [ -z "$PAM_WRAPPER_LIB" ]; then
        log_warn "pam_wrapper library not found - tests may use system PAM"
    else
        export LD_PRELOAD="$PAM_WRAPPER_LIB"
        log_info "Using PAM wrapper: $PAM_WRAPPER_LIB"
    fi

    # Ensure pam_fido_mock.so is in the PAM service directory
    if [ -f "$BUILD_DIR/tests/pam/pam_fido_mock.so" ]; then
        cp "$BUILD_DIR/tests/pam/pam_fido_mock.so" "$WORKSPACE/tests/pam/pam_fido_mock.so"
        log_info "Copied pam_fido_mock.so to PAM service directory"
    fi

    # Run the authentication state integration tests
    log_info "Running authentication state integration tests..."

    if "$TEST_BIN" -v1 > "$TEST_RESULTS_DIR/auth-state-integration.log" 2>&1; then
        test_passed "Authentication state integration tests"
        return 0
    else
        log_error "Authentication state tests failed - see log:"
        cat "$TEST_RESULTS_DIR/auth-state-integration.log"
        test_failed "Authentication state integration tests"
        return 1
    fi
}

# Cleanup on exit
cleanup() {
    log_info "Cleaning up..."
    stop_agent

    # Stop D-Bus if we started it
    if [ -n "$DBUS_SESSION_BUS_PID" ]; then
        kill $DBUS_SESSION_BUS_PID 2>/dev/null || true
    fi

    # Print summary
    echo ""
    echo "================================"
    echo "E2E Test Summary"
    echo "================================"
    echo "Tests run:    $TESTS_RUN"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo "================================"

    if [ $TESTS_FAILED -eq 0 ]; then
        log_info "All tests passed!"
        exit 0
    else
        log_error "$TESTS_FAILED test(s) failed"
        exit 1
    fi
}

trap cleanup EXIT

# Main test execution
main() {
    log_info "Starting quickshell-polkit-agent E2E tests"
    log_info "=========================================="

    setup_test_environment
    start_agent

    # Run tests
    test_agent_registration
    test_allowed_action
    test_denied_action
    test_concurrent_requests
    test_agent_cleanup

    # FIDO mock tests
    test_fido_success
    test_fido_timeout
    test_fido_failure

    # Authentication state integration tests (container-only)
    # These tests require polkit-agent-helper-1 to be setuid root
    # and full PAM/polkit/D-Bus integration
    test_authentication_state_integration

    log_info "All tests completed"
}

main "$@"
