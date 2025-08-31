import QtQuick
import Quickshell.Io

Item {
    id: polkitAgent
    
    // Public API
    signal showAuthDialog(string actionId, string message, string iconName)
    signal authorizationResult(bool authorized, string actionId)
    signal authorizationError(string error)
    signal connected()
    signal disconnected()
    
    property bool isConnected: socket.running
    
    // Request authorization for an action
    function checkAuthorization(actionId, details) {
        if (!socket.running) {
            console.log("Not connected to polkit agent")
            return false
        }
        
        var message = {
            "type": "check_authorization",
            "action_id": actionId,
            "details": details || ""
        }
        
        socket.write(JSON.stringify(message))
        return true
    }
    
    // Cancel current authorization
    function cancelAuthorization() {
        if (!socket.running) return
        
        var message = {
            "type": "cancel_authorization"
        }
        
        socket.write(JSON.stringify(message))
    }
    
    // Private implementation using Process with netcat
    Process {
        id: socket
        command: [
            "socat", 
            "-", 
            "UNIX-CONNECT:" + socketPath
        ]
        
        property string socketPath: {
            var runtimeDir = Quickshell.env("XDG_RUNTIME_DIR")
            if (runtimeDir) {
                return runtimeDir + "/quickshell-polkit"
            } else {
                return "/tmp/quickshell-polkit-" + Quickshell.env("UID")
            }
        }
        
        stdin: StdinCollector {
            id: stdinCollector
        }
        
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    var message = JSON.parse(this.text)
                    handleMessage(message)
                } catch (e) {
                    console.log("Invalid JSON from polkit agent:", e)
                }
            }
        }
        
        onRunningChanged: {
            if (running) {
                console.log("Connected to quickshell-polkit-agent")
                polkitAgent.connected()
            } else {
                console.log("Disconnected from quickshell-polkit-agent")
                polkitAgent.disconnected()
            }
        }
        
        function write(data) {
            stdinCollector.write(data + "\n")
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
        socket.connectToHost()
    }
}