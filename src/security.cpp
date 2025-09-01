#include "security.h"
#include "logging.h"
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QJsonDocument>
#include <QDateTime>
#include <QDebug>

QByteArray SecurityManager::s_hmacKey;
bool SecurityManager::s_initialized = false;

void SecurityManager::initialize()
{
    if (s_initialized) {
        return;
    }
    
    // Generate a random HMAC key for this session
    s_hmacKey = generateRandomKey(HMAC_KEY_SIZE);
    s_initialized = true;
    
    qCDebug(polkitAgent) << "Security manager initialized with" << HMAC_KEY_SIZE << "byte HMAC key";
    auditLog("SECURITY_INIT", "HMAC authentication enabled", "SUCCESS");
}

QString SecurityManager::generateHMAC(const QByteArray &data)
{
    if (!s_initialized) {
        qCWarning(polkitAgent) << "Security manager not initialized";
        return QString();
    }
    
    QMessageAuthenticationCode mac(QCryptographicHash::Sha256);
    mac.setKey(s_hmacKey);
    mac.addData(data);
    
    return mac.result().toHex();
}

bool SecurityManager::verifyHMAC(const QByteArray &data, const QString &expectedHMAC)
{
    if (!s_initialized) {
        qCWarning(polkitAgent) << "Security manager not initialized";
        return false;
    }
    
    QString computedHMAC = generateHMAC(data);
    bool valid = (computedHMAC == expectedHMAC);
    
    if (!valid) {
        qCWarning(polkitAgent) << "HMAC verification failed";
        auditLog("HMAC_VERIFICATION", "Message authentication failed", "FAILURE");
    }
    
    return valid;
}

QJsonObject SecurityManager::signMessage(const QJsonObject &message)
{
    QJsonObject signedMessage = message;
    
    // Add timestamp for replay protection
    signedMessage["timestamp"] = getCurrentTimestamp();
    
    // Generate HMAC for the message
    QJsonDocument doc(signedMessage);
    QByteArray messageData = doc.toJson(QJsonDocument::Compact);
    QString hmac = generateHMAC(messageData);
    
    signedMessage["hmac"] = hmac;
    
    return signedMessage;
}

bool SecurityManager::verifyMessage(const QJsonObject &message)
{
    if (!message.contains("hmac") || !message.contains("timestamp")) {
        qCWarning(polkitAgent) << "Message missing security fields";
        auditLog("MESSAGE_VERIFICATION", "Missing HMAC or timestamp", "FAILURE");
        return false;
    }
    
    QString providedHMAC = message["hmac"].toString();
    
    // Create message copy without HMAC for verification
    QJsonObject messageForVerification = message;
    messageForVerification.remove("hmac");
    
    QJsonDocument doc(messageForVerification);
    QByteArray messageData = doc.toJson(QJsonDocument::Compact);
    
    // Verify HMAC
    if (!verifyHMAC(messageData, providedHMAC)) {
        return false;
    }
    
    // Check message timestamp for replay protection
    qint64 messageTimestamp = static_cast<qint64>(message["timestamp"].toDouble());
    qint64 currentTime = getCurrentTimestamp();
    qint64 timeDiff = currentTime - messageTimestamp;
    
    // Allow 30 seconds clock skew
    static constexpr qint64 MAX_TIME_SKEW_MS = 30000;
    if (timeDiff > MAX_TIME_SKEW_MS || timeDiff < -MAX_TIME_SKEW_MS) {
        qCWarning(polkitAgent) << "Message timestamp out of acceptable range:" << timeDiff << "ms";
        auditLog("MESSAGE_VERIFICATION", QString("Timestamp skew: %1ms").arg(timeDiff), "FAILURE");
        return false;
    }
    
    return true;
}

bool SecurityManager::isSessionExpired(qint64 sessionStartTime)
{
    qint64 currentTime = getCurrentTimestamp();
    return (currentTime - sessionStartTime) > SESSION_TIMEOUT_MS;
}

qint64 SecurityManager::getCurrentTimestamp()
{
    return QDateTime::currentMSecsSinceEpoch();
}

void SecurityManager::auditLog(const QString &event, const QString &details, const QString &result)
{
    QString auditMessage = formatAuditMessage(event, details, result);
    
    // Log to Qt logging system with special audit category
    qCInfo(polkitAgent) << "AUDIT:" << auditMessage;
    
    // Could also log to syslog, file, or audit daemon here if needed
}

QByteArray SecurityManager::generateRandomKey(int size)
{
    QByteArray key;
    key.reserve(size);
    
    QRandomGenerator *generator = QRandomGenerator::system();
    for (int i = 0; i < size; ++i) {
        key.append(static_cast<char>(generator->bounded(256)));
    }
    
    return key;
}

QString SecurityManager::formatAuditMessage(const QString &event, const QString &details, const QString &result)
{
    QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
    QString message = QString("[%1] event=%2").arg(timestamp, event);
    
    if (!details.isEmpty()) {
        message += QString(" details=\"%1\"").arg(details);
    }
    
    if (!result.isEmpty()) {
        message += QString(" result=%1").arg(result);
    }
    
    return message;
}