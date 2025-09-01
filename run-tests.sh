#!/bin/bash
# Test runner script for quickshell-polkit-agent

set -e

echo "Building and running tests for quickshell-polkit-agent..."

# Create build directory for tests
mkdir -p build-tests
cd build-tests

# Configure with tests enabled
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug

# Build tests
make -j$(nproc)

echo ""
echo "Running tests..."
echo "=================="

# Run tests with detailed output from tests directory
cd tests
ctest --output-on-failure --verbose

echo ""
echo "Test summary:"
echo "============="
ctest --output-on-failure

echo ""
echo "All tests completed!"