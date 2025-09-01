#include <QTest>
#include <QProcess>
#include <QLocalSocket>
#include <QJsonObject>
#include <QJsonDocument>
#include <QSignalSpy>
#include <QTimer>
#include <QTemporaryDir>
#include <QStandardPaths>
#include "../src/security.h"

/**
 * End-to-end tests for the current socat-based PolkitAgent implementation
 * These tests verify the complete flow from QML component through socat to IPC server
 */
class TestE2ECurrent : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();
    
    // Core functionality tests
    void testAgentStartup();
    void testSocatAvailability();
    void testSocketCreation();
    void testQMLComponentLoading();
    void testBasicIPC();
    void testAuthenticationFlow();
    void testErrorHandling();
    void testHeartbeatMechanism();
    void testConnectionRecovery();
    
    // Performance and reliability tests
    void testMultipleConnections();
    void testLongRunningSession();
    void testResourceCleanup();
    
private:
    QString m_socketPath;
    QProcess *m_agentProcess = nullptr;
    QTemporaryDir *m_tempDir = nullptr;
    
    bool startAgent();
    void stopAgent();
    bool waitForSocket(int timeoutMs = 5000);
    QJsonObject sendCommandViaSocat(const QJsonObject &command, bool expectResponse = true);
    QString runSocatCommand(const QString &input);
    void waitMs(int ms);
};

void TestE2ECurrent::initTestCase()
{
    SecurityManager::initialize();
    
    // Create temporary directory for test socket
    m_tempDir = new QTemporaryDir();
    QVERIFY(m_tempDir->isValid());
    
    m_socketPath = m_tempDir->path() + "/quickshell-polkit-test";
    
    qDebug() << "Test socket path:" << m_socketPath;
}

void TestE2ECurrent::cleanupTestCase()
{
    delete m_tempDir;
}

void TestE2ECurrent::init()
{
    // Clean up any existing socket
    QFile::remove(m_socketPath);
    
    // Start fresh agent process for each test
    QVERIFY(startAgent());
    QVERIFY(waitForSocket());
}

void TestE2ECurrent::cleanup()
{
    stopAgent();
    QFile::remove(m_socketPath);
}

void TestE2ECurrent::testAgentStartup()
{
    // Agent should be running
    QVERIFY(m_agentProcess);
    QCOMPARE(m_agentProcess->state(), QProcess::Running);
    
    // Socket should exist
    QVERIFY(QFile::exists(m_socketPath));
    
    // Should be able to connect with socat
    QProcess socatTest;
    socatTest.start("socat", QStringList() << "-" << QString("UNIX-CONNECT:%1").arg(m_socketPath));
    QVERIFY(socatTest.waitForStarted(1000));
    
    socatTest.write("{\"type\":\"heartbeat\"}\n");
    socatTest.closeWriteChannel();
    
    QVERIFY(socatTest.waitForFinished(3000));
    QCOMPARE(socatTest.exitCode(), 0);
}

void TestE2ECurrent::testSocatAvailability()
{
    // Verify socat is available (required dependency)
    QProcess socat;
    socat.start("socat", QStringList() << "-V");
    QVERIFY(socat.waitForStarted(1000));
    QVERIFY(socat.waitForFinished(1000));
    QCOMPARE(socat.exitCode(), 0);
    
    QString output = socat.readAllStandardOutput();
    QVERIFY(output.contains("socat"));
}

void TestE2ECurrent::testSocketCreation()
{
    // Socket should be created
    QFileInfo socketInfo(m_socketPath);
    QVERIFY(socketInfo.exists());
    
    // Should be able to connect
    QLocalSocket client;
    client.connectToServer(m_socketPath);
    QVERIFY(client.waitForConnected(1000));
    
    client.disconnectFromServer();
    if (client.state() != QLocalSocket::UnconnectedState) {
        QVERIFY(client.waitForDisconnected(1000));
    }
}

void TestE2ECurrent::testQMLComponentLoading()
{
    // This test simulates what quickshell would do with the QML component
    // Since we can't run quickshell directly in tests, we simulate the socat calls
    
    // Test connection (simulates PolkitAgent component connecting)
    QString heartbeat = runSocatCommand("{\"type\":\"heartbeat\"}\n");
    QVERIFY(!heartbeat.isEmpty());
    
    // Should receive welcome message first
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(heartbeat.toUtf8(), &error);
    QCOMPARE(error.error, QJsonParseError::NoError);
    
    QJsonObject response = doc.object();
    // Could be welcome or heartbeat_ack, both are valid for connection test
    QVERIFY(response.contains("type"));
}

void TestE2ECurrent::testBasicIPC()
{
    // Test basic IPC message flow
    
    // Send heartbeat
    QJsonObject heartbeat;
    heartbeat["type"] = "heartbeat";
    heartbeat["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
    
    QJsonObject response = sendCommandViaSocat(heartbeat);
    
    QCOMPARE(response["type"].toString(), QString("heartbeat_ack"));
    QVERIFY(response.contains("timestamp"));
}

void TestE2ECurrent::testAuthenticationFlow()
{
    // Test authentication request flow
    
    QJsonObject authRequest;
    authRequest["type"] = "check_authorization";
    authRequest["action_id"] = "org.example.test";
    authRequest["details"] = "Test authorization";
    
    // Send auth request (should not get immediate response since it's async)
    QString output = runSocatCommand(QJsonDocument(authRequest).toJson(QJsonDocument::Compact) + "\n");
    
    // The output might be empty or contain async response
    // In real usage, the agent would send show_auth_dialog back to quickshell
    
    // Test cancel
    QJsonObject cancelRequest;
    cancelRequest["type"] = "cancel_authorization";
    
    QString cancelOutput = runSocatCommand(QJsonDocument(cancelRequest).toJson(QJsonDocument::Compact) + "\n");
    // Cancel doesn't typically send a response
}

void TestE2ECurrent::testErrorHandling()
{
    // Test invalid message handling
    
    // Invalid JSON
    QString invalidResponse = runSocatCommand("invalid json\n");
    // Should handle gracefully (might close connection or send error)
    
    // Invalid message type
    QJsonObject invalidMsg;
    invalidMsg["type"] = "invalid_type";
    
    QJsonObject errorResponse = sendCommandViaSocat(invalidMsg);
    if (!errorResponse.isEmpty()) {
        QCOMPARE(errorResponse["type"].toString(), QString("error"));
        QVERIFY(errorResponse.contains("error"));
    }
    
    // Missing required fields
    QJsonObject incompleteMsg;
    incompleteMsg["type"] = "check_authorization";
    // Missing action_id
    
    QJsonObject errorResponse2 = sendCommandViaSocat(incompleteMsg);
    if (!errorResponse2.isEmpty()) {
        QCOMPARE(errorResponse2["type"].toString(), QString("error"));
        QVERIFY(errorResponse2["error"].toString().contains("action_id"));
    }
}

void TestE2ECurrent::testHeartbeatMechanism()
{
    // Test heartbeat keeps connection alive
    
    for (int i = 0; i < 3; ++i) {
        QJsonObject heartbeat;
        heartbeat["type"] = "heartbeat";
        heartbeat["timestamp"] = static_cast<double>(SecurityManager::getCurrentTimestamp());
        
        QJsonObject response = sendCommandViaSocat(heartbeat);
        QCOMPARE(response["type"].toString(), QString("heartbeat_ack"));
        
        waitMs(100); // Brief delay between heartbeats
    }
}

void TestE2ECurrent::testConnectionRecovery()
{
    // Test that new connections work after disconnect
    
    // Send initial message
    QJsonObject msg1;
    msg1["type"] = "heartbeat";
    QJsonObject response1 = sendCommandViaSocat(msg1);
    QCOMPARE(response1["type"].toString(), QString("heartbeat_ack"));
    
    // Brief delay to ensure connection is closed
    waitMs(100);
    
    // Send another message (new connection)
    QJsonObject msg2;
    msg2["type"] = "heartbeat";
    QJsonObject response2 = sendCommandViaSocat(msg2);
    QCOMPARE(response2["type"].toString(), QString("heartbeat_ack"));
}

void TestE2ECurrent::testMultipleConnections()
{
    // Test behavior with multiple concurrent connections
    // The server should handle only one connection at a time
    
    QProcess socat1, socat2;
    
    // Start first connection
    socat1.start("socat", QStringList() << "-" << QString("UNIX-CONNECT:%1").arg(m_socketPath));
    QVERIFY(socat1.waitForStarted(1000));
    
    // Start second connection
    socat2.start("socat", QStringList() << "-" << QString("UNIX-CONNECT:%1").arg(m_socketPath));
    QVERIFY(socat2.waitForStarted(1000));
    
    // Send message on first connection
    socat1.write("{\"type\":\"heartbeat\"}\n");
    socat1.closeWriteChannel();
    
    // Second connection should be rejected or handled appropriately
    socat2.write("{\"type\":\"heartbeat\"}\n");
    socat2.closeWriteChannel();
    
    QVERIFY(socat1.waitForFinished(3000));
    QVERIFY(socat2.waitForFinished(3000));
    
    // At least one should succeed
    bool oneSucceeded = (socat1.exitCode() == 0) || (socat2.exitCode() == 0);
    QVERIFY(oneSucceeded);
}

void TestE2ECurrent::testLongRunningSession()
{
    // Test session stability over time
    
    for (int i = 0; i < 10; ++i) {
        QJsonObject heartbeat;
        heartbeat["type"] = "heartbeat";
        
        QJsonObject response = sendCommandViaSocat(heartbeat);
        QCOMPARE(response["type"].toString(), QString("heartbeat_ack"));
        
        waitMs(50); // Small delay between requests
    }
}

void TestE2ECurrent::testResourceCleanup()
{
    // Test that resources are properly cleaned up
    
    // Send some messages
    for (int i = 0; i < 5; ++i) {
        QJsonObject msg;
        msg["type"] = "heartbeat";
        sendCommandViaSocat(msg);
    }
    
    // Stop agent
    stopAgent();
    
    // Socket should be cleaned up
    waitMs(500);
    QVERIFY(!QFile::exists(m_socketPath));
}

bool TestE2ECurrent::startAgent()
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
    qDebug() << "Attempting to start agent at:" << agentPath;
    qDebug() << "Test socket path:" << m_socketPath;
    
    m_agentProcess->start(agentPath);
    
    if (!m_agentProcess->waitForStarted(3000)) {
        qWarning() << "Failed to start agent:" << m_agentProcess->errorString();
        qWarning() << "Agent path:" << agentPath;
        qWarning() << "Working directory:" << QCoreApplication::applicationDirPath();
        
        // Check if file exists
        if (!QFile::exists(agentPath)) {
            qWarning() << "Agent executable not found at:" << agentPath;
        }
        
        return false;
    }
    
    qDebug() << "Agent started successfully, PID:" << m_agentProcess->processId();
    
    // Wait a moment and show agent output for debugging
    waitMs(500);
    QByteArray stdout = m_agentProcess->readAllStandardOutput();
    QByteArray stderr = m_agentProcess->readAllStandardError();
    if (!stdout.isEmpty()) {
        qDebug() << "Agent stdout:" << stdout;
    }
    if (!stderr.isEmpty()) {
        qDebug() << "Agent stderr:" << stderr;
    }
    
    return true;
}

void TestE2ECurrent::stopAgent()
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

bool TestE2ECurrent::waitForSocket(int timeoutMs)
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

QJsonObject TestE2ECurrent::sendCommandViaSocat(const QJsonObject &command, bool expectResponse)
{
    QString input = QJsonDocument(command).toJson(QJsonDocument::Compact) + "\n";
    QString output = runSocatCommand(input);
    
    if (!expectResponse || output.isEmpty()) {
        return QJsonObject();
    }
    
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(output.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        qWarning() << "Failed to parse response:" << error.errorString();
        qWarning() << "Raw output:" << output;
        return QJsonObject();
    }
    
    return doc.object();
}

QString TestE2ECurrent::runSocatCommand(const QString &input)
{
    QProcess socat;
    socat.start("socat", QStringList() << "-" << QString("UNIX-CONNECT:%1").arg(m_socketPath));
    
    if (!socat.waitForStarted(1000)) {
        qWarning() << "Failed to start socat:" << socat.errorString();
        return QString();
    }
    
    socat.write(input.toUtf8());
    socat.closeWriteChannel();
    
    if (!socat.waitForFinished(3000)) {
        qWarning() << "Socat command timed out";
        socat.kill();
        return QString();
    }
    
    QString output = socat.readAllStandardOutput();
    
    if (socat.exitCode() != 0) {
        QString error = socat.readAllStandardError();
        qWarning() << "Socat failed with exit code:" << socat.exitCode();
        qWarning() << "Error output:" << error;
    }
    
    // Return only the last line (most recent message) for tests that expect one response
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    return lines.isEmpty() ? output : lines.last();
}

void TestE2ECurrent::waitMs(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

QTEST_MAIN(TestE2ECurrent)
#include "test-e2e-current.moc"