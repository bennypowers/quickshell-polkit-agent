#include <QTest>
#include <QJsonObject>
#include <QJsonDocument>
#include "../src/message-validator.h"

class TestMessageValidator : public QObject
{
    Q_OBJECT

private slots:
    void testValidCheckAuthorization();
    void testInvalidCheckAuthorization();
    void testValidCancelAuthorization();
    void testInvalidCancelAuthorization();
    void testValidSubmitAuthentication();
    void testInvalidSubmitAuthentication();
    void testValidHeartbeat();
    void testInvalidHeartbeat();
    void testMissingMessageType();
    void testInvalidMessageType();
    void testStringValidation();
    void testLengthLimits();
    void testSecurityValidation();
};

void TestMessageValidator::testValidCheckAuthorization()
{
    QJsonObject message;
    message["type"] = "check_authorization";
    message["action_id"] = "org.example.test";
    message["details"] = "Test details";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(result.valid);
    QVERIFY(result.error.isEmpty());
}

void TestMessageValidator::testInvalidCheckAuthorization()
{
    // Missing action_id
    QJsonObject message1;
    message1["type"] = "check_authorization";
    ValidationResult result1 = MessageValidator::validateMessage(message1);
    QVERIFY(!result1.valid);
    QVERIFY(result1.error.contains("action_id"));
    
    // Empty action_id
    QJsonObject message2;
    message2["type"] = "check_authorization";
    message2["action_id"] = "";
    ValidationResult result2 = MessageValidator::validateMessage(message2);
    QVERIFY(!result2.valid);
    QVERIFY(result2.error.contains("empty"));
    
    // Invalid action_id format (no dots)
    QJsonObject message3;
    message3["type"] = "check_authorization";
    message3["action_id"] = "invalidactionid";
    ValidationResult result3 = MessageValidator::validateMessage(message3);
    QVERIFY(!result3.valid);
    QVERIFY(result3.error.contains("dot"));
}

void TestMessageValidator::testValidCancelAuthorization()
{
    QJsonObject message;
    message["type"] = "cancel_authorization";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(result.valid);
    QVERIFY(result.error.isEmpty());
}

void TestMessageValidator::testInvalidCancelAuthorization()
{
    // Unexpected field
    QJsonObject message;
    message["type"] = "cancel_authorization";
    message["unexpected_field"] = "value";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("Unexpected field"));
}

void TestMessageValidator::testValidSubmitAuthentication()
{
    QJsonObject message;
    message["type"] = "submit_authentication";
    message["cookie"] = "test-cookie-123";
    message["response"] = "test-response";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(result.valid);
    QVERIFY(result.error.isEmpty());
}

void TestMessageValidator::testInvalidSubmitAuthentication()
{
    // Missing cookie
    QJsonObject message1;
    message1["type"] = "submit_authentication";
    message1["response"] = "test-response";
    ValidationResult result1 = MessageValidator::validateMessage(message1);
    QVERIFY(!result1.valid);
    QVERIFY(result1.error.contains("cookie"));
    
    // Invalid cookie characters
    QJsonObject message2;
    message2["type"] = "submit_authentication";
    message2["cookie"] = "invalid@cookie#chars";
    message2["response"] = "test-response";
    ValidationResult result2 = MessageValidator::validateMessage(message2);
    QVERIFY(!result2.valid);
    QVERIFY(result2.error.contains("invalid characters"));
}

void TestMessageValidator::testValidHeartbeat()
{
    QJsonObject message1;
    message1["type"] = "heartbeat";
    ValidationResult result1 = MessageValidator::validateMessage(message1);
    QVERIFY(result1.valid);
    
    // With timestamp
    QJsonObject message2;
    message2["type"] = "heartbeat";
    message2["timestamp"] = 1234567890.0;
    ValidationResult result2 = MessageValidator::validateMessage(message2);
    QVERIFY(result2.valid);
}

void TestMessageValidator::testInvalidHeartbeat()
{
    // Invalid timestamp type
    QJsonObject message;
    message["type"] = "heartbeat";
    message["timestamp"] = "not-a-number";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("timestamp"));
}

void TestMessageValidator::testMissingMessageType()
{
    QJsonObject message;
    message["action_id"] = "org.example.test";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("type"));
}

void TestMessageValidator::testInvalidMessageType()
{
    QJsonObject message;
    message["type"] = "invalid_type";
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("Invalid message type"));
}

void TestMessageValidator::testStringValidation()
{
    // Test maximum length enforcement
    QString longString(5000, 'x'); // Exceeds MAX_STRING_LENGTH
    
    QJsonObject message;
    message["type"] = "check_authorization";
    message["action_id"] = "org.example.test";
    message["details"] = longString;
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("maximum length"));
}

void TestMessageValidator::testLengthLimits()
{
    // Test action_id length limit
    QString longActionId(300, 'x'); // Exceeds MAX_ACTION_ID_LENGTH
    
    QJsonObject message;
    message["type"] = "check_authorization";
    message["action_id"] = longActionId;
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("maximum length"));
}

void TestMessageValidator::testSecurityValidation()
{
    // Test that non-string types are rejected
    QJsonObject message;
    message["type"] = "check_authorization";
    message["action_id"] = 123; // Should be string
    
    ValidationResult result = MessageValidator::validateMessage(message);
    QVERIFY(!result.valid);
    QVERIFY(result.error.contains("must be a string"));
}

QTEST_MAIN(TestMessageValidator)
#include "test-message-validator.moc"