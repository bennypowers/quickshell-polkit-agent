#pragma once

#include <QString>
#include <QByteArray>
#include <QJsonObject>
#include <QDateTime>

class SecurityManager
{
public:
    // Initialize security manager with random key generation
    static void initialize();
    
    // HMAC authentication for IPC messages
    static QString generateHMAC(const QByteArray &data);
    static bool verifyHMAC(const QByteArray &data, const QString &expectedHMAC);
    
    // Message authentication helpers
    static QJsonObject signMessage(const QJsonObject &message);
    static bool verifyMessage(const QJsonObject &message);
    
    // Session timeout management
    static bool isSessionExpired(qint64 sessionStartTime);
    static qint64 getCurrentTimestamp();
    
    // Audit logging
    static void auditLog(const QString &event, const QString &details = QString(), 
                        const QString &result = QString());
    
    // Security configuration
    static constexpr int SESSION_TIMEOUT_MS = 300000; // 5 minutes
    static constexpr int HMAC_KEY_SIZE = 32; // 256 bits
    
private:
    static QByteArray s_hmacKey;
    static bool s_initialized;
    
    static QByteArray generateRandomKey(int size);
    static QString formatAuditMessage(const QString &event, const QString &details, 
                                    const QString &result);
};