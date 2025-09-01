#include <QTest>
#include <QJsonObject>
#include <QJsonDocument>
#include <QThread>
#include "../src/security.h"

class TestSecurityManager : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testInitialization();
    void testHMACGeneration();
    void testHMACVerification();
    void testMessageSigning();
    void testMessageVerification();
    void testSessionTimeout();
    void testTimestampValidation();
    void testAuditLogging();
    void testReplayProtection();
    
private:
    void waitMs(int ms);
};

void TestSecurityManager::initTestCase()
{
    // Initialize security manager for tests
    SecurityManager::initialize();
}

void TestSecurityManager::testInitialization()
{
    // Test that security manager initializes properly
    SecurityManager::initialize();
    
    // Should be able to generate HMAC after initialization
    QByteArray testData("test data");
    QString hmac = SecurityManager::generateHMAC(testData);
    QVERIFY(!hmac.isEmpty());
    QCOMPARE(hmac.length(), 64); // SHA256 hex = 64 chars
}

void TestSecurityManager::testHMACGeneration()
{
    QByteArray data1("test data 1");
    QByteArray data2("test data 2");
    QByteArray data3("test data 1"); // Same as data1
    
    QString hmac1 = SecurityManager::generateHMAC(data1);
    QString hmac2 = SecurityManager::generateHMAC(data2);
    QString hmac3 = SecurityManager::generateHMAC(data3);
    
    // Different data should produce different HMACs
    QVERIFY(hmac1 != hmac2);
    
    // Same data should produce same HMAC
    QCOMPARE(hmac1, hmac3);
    
    // HMACs should be valid hex strings
    QVERIFY(hmac1.length() == 64);
    QVERIFY(hmac2.length() == 64);
    
    // Should only contain hex characters
    QRegularExpression hexRegex("^[0-9a-f]+$");
    QVERIFY(hexRegex.match(hmac1).hasMatch());
    QVERIFY(hexRegex.match(hmac2).hasMatch());
}

void TestSecurityManager::testHMACVerification()
{
    QByteArray testData("test verification data");
    QString correctHMAC = SecurityManager::generateHMAC(testData);
    QString incorrectHMAC = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    // Correct HMAC should verify
    QVERIFY(SecurityManager::verifyHMAC(testData, correctHMAC));
    
    // Incorrect HMAC should not verify
    QVERIFY(!SecurityManager::verifyHMAC(testData, incorrectHMAC));
    
    // Modified data should not verify with original HMAC
    QByteArray modifiedData("modified test data");
    QVERIFY(!SecurityManager::verifyHMAC(modifiedData, correctHMAC));
}

void TestSecurityManager::testMessageSigning()
{
    QJsonObject message;
    message["type"] = "test_message";
    message["data"] = "test data";
    
    QJsonObject signedMessage = SecurityManager::signMessage(message);
    
    // Should contain original fields
    QCOMPARE(signedMessage["type"].toString(), QString("test_message"));
    QCOMPARE(signedMessage["data"].toString(), QString("test data"));
    
    // Should have added security fields
    QVERIFY(signedMessage.contains("timestamp"));
    QVERIFY(signedMessage.contains("hmac"));
    
    // Timestamp should be reasonable (within last few seconds)
    qint64 timestamp = static_cast<qint64>(signedMessage["timestamp"].toDouble());
    qint64 now = SecurityManager::getCurrentTimestamp();
    QVERIFY(qAbs(now - timestamp) < 5000); // Within 5 seconds
    
    // HMAC should be valid hex string
    QString hmac = signedMessage["hmac"].toString();
    QCOMPARE(hmac.length(), 64);
    QRegularExpression hexRegex("^[0-9a-f]+$");
    QVERIFY(hexRegex.match(hmac).hasMatch());
}

void TestSecurityManager::testMessageVerification()
{
    QJsonObject message;
    message["type"] = "test_message";
    message["data"] = "test data";
    
    QJsonObject signedMessage = SecurityManager::signMessage(message);
    
    // Valid signed message should verify
    QVERIFY(SecurityManager::verifyMessage(signedMessage));
    
    // Message without HMAC should not verify
    QJsonObject messageNoHMAC = message;
    messageNoHMAC["timestamp"] = SecurityManager::getCurrentTimestamp();
    QVERIFY(!SecurityManager::verifyMessage(messageNoHMAC));
    
    // Message without timestamp should not verify
    QJsonObject messageNoTimestamp = message;
    messageNoTimestamp["hmac"] = "dummy_hmac";
    QVERIFY(!SecurityManager::verifyMessage(messageNoTimestamp));
    
    // Message with tampered data should not verify
    QJsonObject tamperedMessage = signedMessage;
    tamperedMessage["data"] = "tampered data";
    QVERIFY(!SecurityManager::verifyMessage(tamperedMessage));
}

void TestSecurityManager::testSessionTimeout()
{
    qint64 now = SecurityManager::getCurrentTimestamp();
    qint64 recentTime = now - 1000; // 1 second ago
    qint64 oldTime = now - (SecurityManager::SESSION_TIMEOUT_MS + 1000); // Expired
    
    // Recent session should not be expired
    QVERIFY(!SecurityManager::isSessionExpired(recentTime));
    
    // Old session should be expired
    QVERIFY(SecurityManager::isSessionExpired(oldTime));
    
    // Current time should not be expired
    QVERIFY(!SecurityManager::isSessionExpired(now));
}

void TestSecurityManager::testTimestampValidation()
{
    QJsonObject message;
    message["type"] = "test_message";
    message["data"] = "test data";
    
    // Create message with very old timestamp
    QJsonObject oldMessage = message;
    oldMessage["timestamp"] = SecurityManager::getCurrentTimestamp() - 60000; // 60 seconds ago
    oldMessage["hmac"] = SecurityManager::generateHMAC(QJsonDocument(oldMessage).toJson(QJsonDocument::Compact));
    
    // Old message should not verify due to timestamp
    QVERIFY(!SecurityManager::verifyMessage(oldMessage));
    
    // Create message with future timestamp
    QJsonObject futureMessage = message;
    futureMessage["timestamp"] = SecurityManager::getCurrentTimestamp() + 60000; // 60 seconds in future
    futureMessage["hmac"] = SecurityManager::generateHMAC(QJsonDocument(futureMessage).toJson(QJsonDocument::Compact));
    
    // Future message should not verify due to timestamp
    QVERIFY(!SecurityManager::verifyMessage(futureMessage));
}

void TestSecurityManager::testAuditLogging()
{
    // This test mainly verifies that audit logging doesn't crash
    // In a real system, you'd capture and verify log output
    
    SecurityManager::auditLog("TEST_EVENT", "Test details", "SUCCESS");
    SecurityManager::auditLog("TEST_EVENT_2", "", "FAILURE");
    SecurityManager::auditLog("TEST_EVENT_3");
    
    // If we get here without crashing, audit logging works
    QVERIFY(true);
}

void TestSecurityManager::testReplayProtection()
{
    QJsonObject message;
    message["type"] = "test_message";
    message["data"] = "test data";
    
    QJsonObject signedMessage = SecurityManager::signMessage(message);
    
    // First verification should succeed
    QVERIFY(SecurityManager::verifyMessage(signedMessage));
    
    // Same message should still verify (we don't implement one-time nonces)
    QVERIFY(SecurityManager::verifyMessage(signedMessage));
    
    // But a message with old timestamp should fail
    QJsonObject oldSignedMessage = signedMessage;
    oldSignedMessage["timestamp"] = SecurityManager::getCurrentTimestamp() - 60000;
    
    // Need to regenerate HMAC with old timestamp
    QJsonObject messageForHMAC = oldSignedMessage;
    messageForHMAC.remove("hmac");
    QByteArray messageData = QJsonDocument(messageForHMAC).toJson(QJsonDocument::Compact);
    oldSignedMessage["hmac"] = SecurityManager::generateHMAC(messageData);
    
    QVERIFY(!SecurityManager::verifyMessage(oldSignedMessage));
}

void TestSecurityManager::waitMs(int ms)
{
    QThread::msleep(ms);
}

QTEST_MAIN(TestSecurityManager)
#include "test-security.moc"