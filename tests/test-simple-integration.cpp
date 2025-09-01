#include <QTest>
#include <QJsonObject>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QLocalServer>
#include <QSignalSpy>
#include <QTimer>
#include "../src/message-validator.h"
#include "../src/security.h"

class TestSimpleIntegration : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testMessageValidationIntegration();
    void testSecurityIntegration();
    void testSocketCommunication();
    
private:
    void waitMs(int ms);
};

void TestSimpleIntegration::initTestCase()
{
    SecurityManager::initialize();
}

void TestSimpleIntegration::testMessageValidationIntegration()
{
    // Test that message validation integrates properly with JSON parsing
    
    // Valid message as JSON string
    QString validJson = R"({"type":"check_authorization","action_id":"org.example.test"})";
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(validJson.toUtf8(), &error);
    
    QCOMPARE(error.error, QJsonParseError::NoError);
    
    ValidationResult result = MessageValidator::validateMessage(doc.object());
    QVERIFY(result.valid);
    
    // Invalid message as JSON string
    QString invalidJson = R"({"type":"check_authorization"})"; // Missing action_id
    QJsonDocument invalidDoc = QJsonDocument::fromJson(invalidJson.toUtf8(), &error);
    
    QCOMPARE(error.error, QJsonParseError::NoError); // JSON is valid
    
    ValidationResult invalidResult = MessageValidator::validateMessage(invalidDoc.object());
    QVERIFY(!invalidResult.valid); // But message validation fails
}

void TestSimpleIntegration::testSecurityIntegration()
{
    // Test that security features work together
    
    QJsonObject message;
    message["type"] = "check_authorization";
    message["action_id"] = "org.example.test";
    
    // Sign the message
    QJsonObject signedMessage = SecurityManager::signMessage(message);
    
    // Verify the signed message
    QVERIFY(SecurityManager::verifyMessage(signedMessage));
    
    // Convert to JSON and back (simulating network transmission)
    QJsonDocument doc(signedMessage);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    
    QJsonParseError error;
    QJsonDocument receivedDoc = QJsonDocument::fromJson(jsonData, &error);
    QCOMPARE(error.error, QJsonParseError::NoError);
    
    // Should still verify after JSON round-trip
    QVERIFY(SecurityManager::verifyMessage(receivedDoc.object()));
    
    // Should pass message validation too (remove HMAC field first since validator doesn't expect it)
    QJsonObject messageForValidation = receivedDoc.object();
    messageForValidation.remove("hmac");
    messageForValidation.remove("timestamp");
    ValidationResult validation = MessageValidator::validateMessage(messageForValidation);
    QVERIFY(validation.valid);
}

void TestSimpleIntegration::testSocketCommunication()
{
    // Test basic socket communication without full IPC server
    
    QString socketPath = "/tmp/test-quickshell-simple";
    QFile::remove(socketPath);
    
    // Create a simple server
    QLocalServer server;
    QVERIFY(server.listen(socketPath));
    
    // Connect client
    QLocalSocket client;
    client.connectToServer(socketPath);
    QVERIFY(client.waitForConnected(1000));
    
    // Wait for server to accept connection
    QVERIFY(server.waitForNewConnection(1000));
    QLocalSocket *serverSocket = server.nextPendingConnection();
    QVERIFY(serverSocket);
    
    // Test sending a valid message
    QJsonObject message;
    message["type"] = "heartbeat";
    message["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
    
    QJsonDocument doc(message);
    QByteArray data = doc.toJson(QJsonDocument::Compact) + "\n";
    
    client.write(data);
    client.flush();
    
    // Server should receive the message
    QVERIFY(serverSocket->waitForReadyRead(1000));
    QByteArray receivedData = serverSocket->readLine();
    
    QJsonParseError error;
    QJsonDocument receivedDoc = QJsonDocument::fromJson(receivedData, &error);
    QCOMPARE(error.error, QJsonParseError::NoError);
    
    // Validate the received message
    ValidationResult validation = MessageValidator::validateMessage(receivedDoc.object());
    QVERIFY(validation.valid);
    
    // Clean up
    serverSocket->close();
    client.close();
    server.close();
    QFile::remove(socketPath);
}

void TestSimpleIntegration::waitMs(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

QTEST_MAIN(TestSimpleIntegration)
#include "test-simple-integration.moc"