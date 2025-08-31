import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io

ShellRoot {
    // Test our polkit integration
    PolkitAgent {
        id: polkitAgent

        onShowAuthDialog: function(actionId, message, iconName) {
            console.log("Show auth dialog for:", actionId)
            console.log("Message:", message)
            authDialog.actionId = actionId
            authDialog.message = message
            authDialog.visible = true
        }

        onAuthorizationResult: function(authorized, actionId) {
            console.log("Authorization result for", actionId + ":", authorized ? "GRANTED" : "DENIED")
            authDialog.visible = false

            if (authorized) {
                resultText.text = "✅ Authorization GRANTED for " + actionId
            } else {
                resultText.text = "❌ Authorization DENIED for " + actionId
            }
        }

        onAuthorizationError: function(error) {
            console.log("Authorization error:", error)
            authDialog.visible = false
            resultText.text = "⚠️ Error: " + error
        }

        onConnected: {
            console.log("✅ Connected to quickshell-polkit-agent")
            statusText.text = "Connected to polkit agent"
            statusText.color = "green"
        }

        onDisconnected: {
            console.log("❌ Disconnected from quickshell-polkit-agent")
            statusText.text = "Disconnected from polkit agent"
            statusText.color = "red"
        }
    }

    // Test window
    Window {
        id: testWindow
        visible: true
        width: 600
        height: 400
        title: "Quickshell Polkit Agent Test"

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 20
            spacing: 20

            Text {
                text: "Quickshell Polkit Agent Test"
                font.pixelSize: 24
                font.bold: true
                Layout.alignment: Qt.AlignHCenter
            }

            Text {
                id: statusText
                text: "Connecting to polkit agent..."
                color: "orange"
                Layout.alignment: Qt.AlignHCenter
            }

            Text {
                id: resultText
                text: "Ready to test authorization"
                Layout.alignment: Qt.AlignHCenter
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }

            GridLayout {
                columns: 2
                Layout.fillWidth: true

                Button {
                    text: "Test SystemD"
                    Layout.fillWidth: true
                    onClicked: {
                        polkitAgent.checkAuthorization("org.freedesktop.systemd1.manage-units")
                    }
                }

                Button {
                    text: "Test Network"
                    Layout.fillWidth: true
                    onClicked: {
                        polkitAgent.checkAuthorization("org.freedesktop.NetworkManager.settings.modify.system")
                    }
                }

                Button {
                    text: "Test Package Manager"
                    Layout.fillWidth: true
                    onClicked: {
                        polkitAgent.checkAuthorization("org.freedesktop.packagekit.package-install")
                    }
                }

                Button {
                    text: "Test Custom Action"
                    Layout.fillWidth: true
                    onClicked: {
                        polkitAgent.checkAuthorization("com.example.test.action")
                    }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }

    // Authentication dialog overlay
    Window {
        id: authDialog
        visible: false
        width: 400
        height: 250
        title: "Authentication Required"

        property string actionId: ""
        property string message: ""

        Rectangle {
            anchors.fill: parent
            color: "#1e1e2e"  // Catppuccin base
            border.color: "#89b4fa"  // Catppuccin blue
            border.width: 2

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 20
                spacing: 20

                Text {
                    text: "🔐 Authentication Required"
                    color: "#cdd6f4"  // Catppuccin text
                    font.pixelSize: 18
                    font.bold: true
                    Layout.alignment: Qt.AlignHCenter
                }

                Text {
                    text: authDialog.message
                    color: "#bac2de"  // Catppuccin subtext1
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    Layout.alignment: Qt.AlignHCenter
                    horizontalAlignment: Text.AlignHCenter
                }

                Text {
                    text: "Action: " + authDialog.actionId
                    color: "#fab387"  // Catppuccin peach
                    font.pixelSize: 10
                    Layout.alignment: Qt.AlignHCenter
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 60
                    color: "#313244"  // Catppuccin surface0
                    border.color: "#89b4fa"
                    border.width: 1
                    radius: 8

                    Text {
                        anchors.centerIn: parent
                        text: "🔑 Please authenticate using your system method\n(password, security key, etc.)"
                        color: "#cdd6f4"
                        horizontalAlignment: Text.AlignHCenter
                    }
                }

                Button {
                    text: "Cancel"
                    Layout.alignment: Qt.AlignHCenter
                    onClicked: {
                        polkitAgent.cancelAuthorization()
                        authDialog.visible = false
                    }
                }
            }
        }
    }
}
