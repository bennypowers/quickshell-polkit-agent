#!/bin/bash
# Runner script for Podman-based e2e tests
#
# This script:
# 1. Builds a container with real polkit daemon
# 2. Runs the e2e tests inside the container
# 3. Reports results

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONTAINER_IMAGE="quickshell-polkit-e2e:latest"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if podman is available
if ! command -v podman &> /dev/null; then
    log_error "podman not found. Please install podman."
    log_info "  Fedora: sudo dnf install podman"
    log_info "  Debian/Ubuntu: sudo apt install podman"
    exit 1
fi

# Build container
log_info "Building e2e test container..."
cd "$PROJECT_ROOT"

if podman build -f tests/e2e/Containerfile.e2e -t "$CONTAINER_IMAGE" .; then
    log_info "Container built successfully"
else
    log_error "Failed to build container"
    exit 1
fi

# Run tests in container
log_info "Running e2e tests in container..."

# Create test-results directory if it doesn't exist
mkdir -p "$SCRIPT_DIR/test-results"

# Run with:
# - Privileged mode for polkit daemon
# - Volume mount for test results
# - systemd cgroup support
podman run \
    --rm \
    --privileged \
    --systemd=always \
    -v "$SCRIPT_DIR/test-results:/workspace/tests/e2e/test-results:Z" \
    "$CONTAINER_IMAGE" \
    /workspace/tests/e2e/run-e2e-tests.sh

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    log_info "E2E tests passed!"
else
    log_error "E2E tests failed with exit code $EXIT_CODE"

    # Show agent log if available
    if [ -f "$SCRIPT_DIR/test-results/agent.log" ]; then
        log_warn "Agent log:"
        cat "$SCRIPT_DIR/test-results/agent.log"
    fi
fi

exit $EXIT_CODE
