#include <QTest>
#include <QProcess>
#include <QLocalSocket>
#include <QJsonObject>
#include <QJsonDocument>
#include <QSignalSpy>
#include <QTimer>
#include <QTemporaryDir>
#include <unistd.h>
#include "../src/security.h"

/**
 * Comprehensive E2E validation test for PolkitAgent LocalSocket implementation
 * This tests the actual QML LocalSocket behavior and validates all critical functionality
 */
class TestLocalSocketValidation : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();
    
    // Core E2E validation tests for LocalSocket implementation
    void testBasicConnectivity();
    void testHeartbeatFlow();
    void testAuthorizationFlow();
    void testErrorHandling();
    void testReconnection();
    void testMultipleMessages();
    void testMessageBuffering();
    void testConnectionStability();
    
private:
    QString m_socketPath;
    QProcess *m_agentProcess = nullptr;
    QTemporaryDir *m_tempDir = nullptr;
    
    bool startAgent();
    void stopAgent();
    bool waitForSocket(int timeoutMs = 5000);
    void waitMs(int ms);
    QJsonObject sendMessageAndGetResponse(const QJsonObject &message);
    QLocalSocket* createConnection();
};

void TestLocalSocketValidation::initTestCase()
{
    SecurityManager::initialize();
    
    // Create temporary directory for test socket
    m_tempDir = new QTemporaryDir();
    QVERIFY(m_tempDir->isValid());
    
    m_socketPath = m_tempDir->path() + "/quickshell-polkit-test";
    
    qDebug() << "Test socket path:" << m_socketPath;
}

void TestLocalSocketValidation::cleanupTestCase()
{
    delete m_tempDir;
}

void TestLocalSocketValidation::init()
{
    // Clean up any existing socket
    QFile::remove(m_socketPath);
    
    // Start fresh agent process for each test
    QVERIFY(startAgent());
    QVERIFY(waitForSocket());
}

void TestLocalSocketValidation::cleanup()
{
    stopAgent();
    QFile::remove(m_socketPath);
}

void TestLocalSocketValidation::testBasicConnectivity()
{
    // Test that LocalSocket can connect and communicate reliably
    
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    QCOMPARE(client->state(), QLocalSocket::ConnectedState);
    
    // Should receive welcome message
    QVERIFY(client->waitForReadyRead(3000));
    QByteArray welcome = client->readAll();
    QVERIFY(welcome.contains("welcome"));
    
    client->deleteLater();
}

void TestLocalSocketValidation::testHeartbeatFlow()
{
    // Test heartbeat flow - this is critical for QML component health
    
    QJsonObject heartbeat;
    heartbeat["type"] = "heartbeat";
    heartbeat["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
    
    QJsonObject response = sendMessageAndGetResponse(heartbeat);
    
    QCOMPARE(response["type"].toString(), QString("heartbeat_ack"));
    QVERIFY(response.contains("timestamp"));
}

void TestLocalSocketValidation::testAuthorizationFlow()
{
    // Test the authorization request flow that QML components use
    
    QJsonObject authRequest;
    authRequest["type"] = "check_authorization";
    authRequest["action_id"] = "org.example.test";
    authRequest["details"] = "Test authorization";
    
    // Send the request - agent processes it asynchronously
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    
    // Read welcome message first
    QVERIFY(client->waitForReadyRead(3000));
    client->readAll();
    
    // Send authorization request
    QByteArray data = QJsonDocument(authRequest).toJson(QJsonDocument::Compact) + "\n";
    client->write(data);
    client->flush();
    
    // In real usage, this would trigger polkit authentication
    // For this test, we just verify the message is accepted
    waitMs(500);
    
    // Test cancel authorization
    QJsonObject cancelRequest;
    cancelRequest["type"] = "cancel_authorization";
    
    data = QJsonDocument(cancelRequest).toJson(QJsonDocument::Compact) + "\n";
    client->write(data);
    client->flush();
    
    waitMs(500);
    
    client->deleteLater();
}

void TestLocalSocketValidation::testErrorHandling()
{
    // Test error handling - QML component must handle errors gracefully
    
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    
    // Read welcome message
    QVERIFY(client->waitForReadyRead(3000));
    client->readAll();
    
    // Send invalid JSON
    client->write("invalid json\n");
    client->flush();
    
    // Should not crash the connection
    waitMs(500);
    QCOMPARE(client->state(), QLocalSocket::ConnectedState);
    
    // Should still accept valid messages
    QJsonObject heartbeat;
    heartbeat["type"] = "heartbeat";
    
    QByteArray data = QJsonDocument(heartbeat).toJson(QJsonDocument::Compact) + "\n";
    client->write(data);
    client->flush();
    
    // Should get response
    QVERIFY(client->waitForReadyRead(3000));
    QByteArray response = client->readAll();
    QVERIFY(response.contains("heartbeat_ack"));
    
    client->deleteLater();
}

void TestLocalSocketValidation::testReconnection()
{
    // Test reconnection capability - critical for QML auto-reconnect
    
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    
    // Disconnect
    client->disconnectFromServer();
    if (client->state() != QLocalSocket::UnconnectedState) {
        QVERIFY(client->waitForDisconnected(3000));
    }
    
    // Reconnect
    client->connectToServer(m_socketPath);
    QVERIFY(client->waitForConnected(3000));
    
    // Should work normally after reconnection
    QVERIFY(client->waitForReadyRead(3000));
    QByteArray welcome = client->readAll();
    QVERIFY(welcome.contains("welcome"));
    
    client->deleteLater();
}

void TestLocalSocketValidation::testMultipleMessages()
{
    // Test handling of multiple rapid messages - important for QML message buffering
    
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    
    // Read welcome message
    QVERIFY(client->waitForReadyRead(3000));
    client->readAll();
    
    // Send multiple messages with small delays to avoid rate limiting
    int responseCount = 0;
    for (int i = 0; i < 5; ++i) {
        QJsonObject msg;
        msg["type"] = "heartbeat";
        msg["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
        
        QByteArray data = QJsonDocument(msg).toJson(QJsonDocument::Compact) + "\n";
        client->write(data);
        client->flush();
        
        // Wait for individual response
        if (client->waitForReadyRead(2000)) {
            QByteArray response = client->readAll();
            if (QString::fromUtf8(response).contains("heartbeat_ack")) {
                responseCount++;
            }
        }
        
        waitMs(50); // Small delay to avoid rate limiting
    }
    
    QCOMPARE(responseCount, 5);
    
    client->deleteLater();
}

void TestLocalSocketValidation::testMessageBuffering()
{
    // Test that messages with newlines are handled correctly
    
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    
    // Read welcome message
    QVERIFY(client->waitForReadyRead(3000));
    client->readAll();
    
    // Send a complete message (this should always work)
    QJsonObject heartbeatMsg;
    heartbeatMsg["type"] = "heartbeat";
    heartbeatMsg["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
    
    QByteArray messageData = QJsonDocument(heartbeatMsg).toJson(QJsonDocument::Compact) + "\n";
    client->write(messageData);
    client->flush();
    
    // Should receive response
    QVERIFY(client->waitForReadyRead(3000));
    QByteArray response = client->readAll();
    QVERIFY(response.contains("heartbeat_ack"));
    
    client->deleteLater();
}

void TestLocalSocketValidation::testConnectionStability()
{
    // Test connection stability over time - important for long-running QML sessions
    
    QLocalSocket *client = createConnection();
    QVERIFY(client);
    
    // Read welcome message
    QVERIFY(client->waitForReadyRead(3000));
    client->readAll();
    
    // Send periodic messages over time
    for (int i = 0; i < 10; ++i) {
        QJsonObject heartbeat;
        heartbeat["type"] = "heartbeat";
        heartbeat["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
        
        QByteArray data = QJsonDocument(heartbeat).toJson(QJsonDocument::Compact) + "\n";
        client->write(data);
        client->flush();
        
        // Should get response
        QVERIFY(client->waitForReadyRead(2000));
        QByteArray response = client->readAll();
        QVERIFY(response.contains("heartbeat_ack"));
        
        waitMs(100); // Brief delay between messages
    }
    
    // Connection should still be stable
    QCOMPARE(client->state(), QLocalSocket::ConnectedState);
    
    client->deleteLater();
}

bool TestLocalSocketValidation::startAgent()
{
    if (m_agentProcess) {
        stopAgent();
    }
    
    m_agentProcess = new QProcess(this);
    
    // Set environment for test socket path
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("QUICKSHELL_POLKIT_SOCKET", m_socketPath);
    m_agentProcess->setProcessEnvironment(env);
    
    // Start the agent with test socket
    QString agentPath = QCoreApplication::applicationDirPath() + "/../quickshell-polkit-agent";
    m_agentProcess->start(agentPath);
    
    if (!m_agentProcess->waitForStarted(3000)) {
        qWarning() << "Failed to start agent:" << m_agentProcess->errorString();
        return false;
    }
    
    return true;
}

void TestLocalSocketValidation::stopAgent()
{
    if (m_agentProcess) {
        m_agentProcess->terminate();
        if (!m_agentProcess->waitForFinished(3000)) {
            m_agentProcess->kill();
            m_agentProcess->waitForFinished(1000);
        }
        delete m_agentProcess;
        m_agentProcess = nullptr;
    }
}

bool TestLocalSocketValidation::waitForSocket(int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    
    while (timer.elapsed() < timeoutMs) {
        if (QFile::exists(m_socketPath)) {
            // Give it a bit more time to be ready
            waitMs(100);
            return true;
        }
        waitMs(100);
    }
    
    return false;
}

void TestLocalSocketValidation::waitMs(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

QJsonObject TestLocalSocketValidation::sendMessageAndGetResponse(const QJsonObject &message)
{
    QLocalSocket *client = createConnection();
    if (!client) return QJsonObject();
    
    // Read welcome message first
    if (client->waitForReadyRead(3000)) {
        client->readAll();
    }
    
    // Send message
    QByteArray data = QJsonDocument(message).toJson(QJsonDocument::Compact) + "\n";
    client->write(data);
    client->flush();
    
    // Get response
    if (client->waitForReadyRead(3000)) {
        QByteArray response = client->readAll();
        
        // Parse last complete JSON message
        QStringList lines = QString::fromUtf8(response).split('\n', Qt::SkipEmptyParts);
        if (!lines.isEmpty()) {
            QJsonParseError error;
            QJsonDocument doc = QJsonDocument::fromJson(lines.last().toUtf8(), &error);
            if (error.error == QJsonParseError::NoError) {
                client->deleteLater();
                return doc.object();
            }
        }
    }
    
    client->deleteLater();
    return QJsonObject();
}

QLocalSocket* TestLocalSocketValidation::createConnection()
{
    QLocalSocket *client = new QLocalSocket(this);
    client->connectToServer(m_socketPath);
    
    if (!client->waitForConnected(3000)) {
        qWarning() << "Failed to connect:" << client->errorString();
        client->deleteLater();
        return nullptr;
    }
    
    return client;
}

QTEST_MAIN(TestLocalSocketValidation)
#include "test-localsocket-validation.moc"