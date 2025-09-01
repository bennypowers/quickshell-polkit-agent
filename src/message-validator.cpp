#include "message-validator.h"
#include <QJsonValue>

const QStringList MessageValidator::VALID_MESSAGE_TYPES = {
    "check_authorization",
    "cancel_authorization", 
    "submit_authentication"
};

ValidationResult MessageValidator::validateMessage(const QJsonObject &message)
{
    // First validate message type
    auto typeResult = validateMessageType(message);
    if (!typeResult.valid) {
        return typeResult;
    }
    
    QString type = message["type"].toString();
    
    // Validate specific message types
    if (type == "check_authorization") {
        return validateCheckAuthorization(message);
    } else if (type == "cancel_authorization") {
        return validateCancelAuthorization(message);
    } else if (type == "submit_authentication") {
        return validateSubmitAuthentication(message);
    }
    
    return ValidationResult::failure("Unknown message type: " + type);
}

ValidationResult MessageValidator::validateCheckAuthorization(const QJsonObject &message)
{
    // action_id is required
    auto actionResult = validateString(message, "action_id", true, MAX_ACTION_ID_LENGTH);
    if (!actionResult.valid) {
        return actionResult;
    }
    
    // details is optional
    if (message.contains("details")) {
        auto detailsResult = validateString(message, "details", false, MAX_STRING_LENGTH);
        if (!detailsResult.valid) {
            return detailsResult;
        }
    }
    
    // Additional security: validate action_id format (basic sanity check)
    QString actionId = message["action_id"].toString();
    if (actionId.isEmpty()) {
        return ValidationResult::failure("action_id cannot be empty");
    }
    
    // Action IDs should be reverse DNS style: org.example.action
    if (!actionId.contains('.')) {
        return ValidationResult::failure("action_id must contain at least one dot (reverse DNS format)");
    }
    
    return ValidationResult::success();
}

ValidationResult MessageValidator::validateCancelAuthorization(const QJsonObject &message)
{
    // Cancel authorization has no additional fields to validate
    // Just ensure no unexpected fields are present
    QStringList allowedKeys = {"type"};
    
    for (auto it = message.begin(); it != message.end(); ++it) {
        if (!allowedKeys.contains(it.key())) {
            return ValidationResult::failure("Unexpected field in cancel_authorization: " + it.key());
        }
    }
    
    return ValidationResult::success();
}

ValidationResult MessageValidator::validateSubmitAuthentication(const QJsonObject &message)
{
    // cookie is required
    auto cookieResult = validateString(message, "cookie", true, MAX_COOKIE_LENGTH);
    if (!cookieResult.valid) {
        return cookieResult;
    }
    
    // response is required
    auto responseResult = validateString(message, "response", true, MAX_RESPONSE_LENGTH);
    if (!responseResult.valid) {
        return responseResult;
    }
    
    // Additional validation for cookie format
    QString cookie = message["cookie"].toString();
    if (cookie.isEmpty()) {
        return ValidationResult::failure("cookie cannot be empty");
    }
    
    // Cookies should be alphanumeric + limited special chars for security
    for (QChar c : cookie) {
        if (!c.isLetterOrNumber() && c != '-' && c != '_') {
            return ValidationResult::failure("cookie contains invalid characters");
        }
    }
    
    return ValidationResult::success();
}

ValidationResult MessageValidator::validateString(const QJsonObject &obj, const QString &key, bool required, int maxLength)
{
    if (!obj.contains(key)) {
        if (required) {
            return ValidationResult::failure("Missing required field: " + key);
        }
        return ValidationResult::success();
    }
    
    QJsonValue value = obj[key];
    if (!value.isString()) {
        return ValidationResult::failure("Field " + key + " must be a string");
    }
    
    QString str = value.toString();
    if (str.length() > maxLength) {
        return ValidationResult::failure(QString("Field %1 exceeds maximum length of %2 characters").arg(key).arg(maxLength));
    }
    
    return ValidationResult::success();
}

ValidationResult MessageValidator::validateMessageType(const QJsonObject &obj)
{
    if (!obj.contains("type")) {
        return ValidationResult::failure("Missing required field: type");
    }
    
    QJsonValue typeValue = obj["type"];
    if (!typeValue.isString()) {
        return ValidationResult::failure("Field 'type' must be a string");
    }
    
    QString type = typeValue.toString();
    if (!VALID_MESSAGE_TYPES.contains(type)) {
        return ValidationResult::failure("Invalid message type: " + type);
    }
    
    return ValidationResult::success();
}