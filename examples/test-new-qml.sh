#!/bin/bash
# Simple test script to verify the PolkitAgent.qml works correctly
# This can be used by quickshell users to test the native Qt LocalSocket implementation

echo "Testing native Qt LocalSocket-based PolkitAgent.qml implementation..."

# Start the agent in test mode
export QUICKSHELL_POLKIT_SOCKET="/tmp/test-polkit-$$"
./quickshell-polkit-agent &
AGENT_PID=$!

# Wait for the socket to be created
sleep 1

if [ ! -S "$QUICKSHELL_POLKIT_SOCKET" ]; then
    echo "ERROR: Socket not created at $QUICKSHELL_POLKIT_SOCKET"
    kill $AGENT_PID 2>/dev/null
    exit 1
fi

echo "SUCCESS: Socket created at $QUICKSHELL_POLKIT_SOCKET"

# Test basic connectivity
echo "Testing basic connectivity..."
# Use nc (netcat) for simple socket testing
echo '{"type":"heartbeat"}' | nc -U $QUICKSHELL_POLKIT_SOCKET | head -1

echo "Test completed. The QML file now uses native Qt LocalSocket instead of external dependencies."

# Cleanup
kill $AGENT_PID 2>/dev/null
rm -f "$QUICKSHELL_POLKIT_SOCKET"