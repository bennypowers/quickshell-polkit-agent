#pragma once

#include <QJsonObject>
#include <QString>
#include <QStringList>

struct ValidationResult {
    bool valid;
    QString error;
    
    ValidationResult(bool v = true, const QString &e = QString()) 
        : valid(v), error(e) {}
    
    static ValidationResult success() { return ValidationResult(true); }
    static ValidationResult failure(const QString &error) { return ValidationResult(false, error); }
};

class MessageValidator
{
public:
    // Validate incoming IPC messages
    static ValidationResult validateMessage(const QJsonObject &message);
    
    // Individual message type validators
    static ValidationResult validateCheckAuthorization(const QJsonObject &message);
    static ValidationResult validateCancelAuthorization(const QJsonObject &message);
    static ValidationResult validateSubmitAuthentication(const QJsonObject &message);
    static ValidationResult validateHeartbeat(const QJsonObject &message);
    
private:
    // Helper validation functions
    static ValidationResult validateString(const QJsonObject &obj, const QString &key, 
                                         bool required = true, int maxLength = 1024);
    static ValidationResult validateMessageType(const QJsonObject &obj);
    
    // Security limits
    static constexpr int MAX_STRING_LENGTH = 4096;
    static constexpr int MAX_ACTION_ID_LENGTH = 256;
    static constexpr int MAX_COOKIE_LENGTH = 128;
    static constexpr int MAX_RESPONSE_LENGTH = 8192; // For passwords/FIDO responses
    
    // Allowed message types
    static const QStringList VALID_MESSAGE_TYPES;
};