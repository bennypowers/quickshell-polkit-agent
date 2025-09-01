import QtQuick
import QtNetwork

Item {
    id: polkitAgent

    // Public API
    signal showAuthDialog(string actionId, string message, string iconName)
    signal authorizationResult(bool authorized, string actionId)
    signal authorizationError(string error)
    signal connected()
    signal disconnected()

    property bool isConnected: socket.state === LocalSocket.ConnectedState

    // Request authorization for an action
    function checkAuthorization(actionId, details) {
        if (socket.state !== LocalSocket.ConnectedState) {
            console.log("Not connected to polkit agent")
            return false
        }

        var message = {
            "type": "check_authorization",
            "action_id": actionId,
            "details": details || ""
        }

        socket.write(JSON.stringify(message) + "\n")
        return true
    }

    // Cancel current authorization
    function cancelAuthorization() {
        if (socket.state !== LocalSocket.ConnectedState) return

        var message = {
            "type": "cancel_authorization"
        }

        socket.write(JSON.stringify(message) + "\n")
    }

    // Private implementation using native Qt LocalSocket
    LocalSocket {
        id: socket

        property string socketPath: {
            var runtimeDir = Quickshell.env("XDG_RUNTIME_DIR")
            if (runtimeDir) {
                return runtimeDir + "/quickshell-polkit"
            } else {
                return "/tmp/quickshell-polkit-" + Quickshell.env("UID")
            }
        }

        property string messageBuffer: ""

        onConnected: {
            console.log("Connected to quickshell-polkit-agent")
            polkitAgent.connected()
        }

        onDisconnected: {
            console.log("Disconnected from quickshell-polkit-agent")
            messageBuffer = ""
            polkitAgent.disconnected()
        }

        onErrorOccurred: function(error) {
            console.log("Socket error:", error)
            messageBuffer = ""
        }

        onReadyRead: {
            var data = readAll()
            messageBuffer += data
            
            // Process complete messages (delimited by newlines)
            var lines = messageBuffer.split('\n')
            messageBuffer = lines.pop() // Keep incomplete line in buffer
            
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].trim()
                if (line.length > 0) {
                    try {
                        var message = JSON.parse(line)
                        handleMessage(message)
                    } catch (e) {
                        console.log("Invalid JSON from polkit agent:", e, "Data:", line)
                    }
                }
            }
        }

        function connectToAgent() {
            if (state === LocalSocket.ConnectedState) {
                return
            }
            connectToServer(socketPath)
        }

        function write(data) {
            if (state === LocalSocket.ConnectedState) {
                writeData(data)
            }
        }
    }

    function handleMessage(message) {
        switch (message.type) {
        case "show_auth_dialog":
            polkitAgent.showAuthDialog(
                message.action_id,
                message.message,
                message.icon_name
            )
            break

        case "authorization_result":
            polkitAgent.authorizationResult(
                message.authorized,
                message.action_id
            )
            break

        case "authorization_error":
            polkitAgent.authorizationError(message.error)
            break

        default:
            console.log("Unknown message type:", message.type)
        }
    }

    // Auto-connect on component creation
    Component.onCompleted: {
        socket.connectToAgent()
    }

    // Auto-reconnect on disconnection (with delay)
    Timer {
        id: reconnectTimer
        interval: 2000 // 2 seconds
        repeat: false
        onTriggered: {
            if (socket.state !== LocalSocket.ConnectedState) {
                console.log("Attempting to reconnect to polkit agent...")
                socket.connectToAgent()
            }
        }
    }

    // Start reconnection timer when disconnected
    Connections {
        target: socket
        function onDisconnected() {
            reconnectTimer.start()
        }
    }
}
