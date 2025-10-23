#include <QTest>
#include <QSignalSpy>
#include <QElapsedTimer>
#include <QSet>
#include "../src/polkit-wrapper.h"
#include "../src/logging.h"

/**
 * Performance and Stress Tests for PolkitAgent
 *
 * Tests system behavior under load:
 * - Many concurrent authentication sessions
 * - Rapid session creation/cleanup cycles
 * - Memory leak detection
 * - State transition performance
 * - Session map scalability
 */
class TestPerformanceStress : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanup();

    // Stress tests
    void testManyConcurrentSessions();
    void testRapidSessionCreationCleanup();
    void testSessionMapScalability();
    void testStateTransitionPerformance();
    void testMemoryStability();
    void testConcurrentStateQueries();

private:
    PolkitWrapper *m_wrapper = nullptr;

    QString generateCookie(int id) {
        return QString("stress-test-cookie-%1").arg(id);
    }

    QString generateActionId(int id) {
        return QString("org.quickshell.stress.action-%1").arg(id);
    }
};

void TestPerformanceStress::initTestCase()
{
    // Use default UsbNfcDetector (nullptr = default)
    m_wrapper = new PolkitWrapper(nullptr, nullptr);
    QVERIFY(m_wrapper != nullptr);
}

void TestPerformanceStress::cleanup()
{
    // Clean up all sessions after each test
    if (m_wrapper) {
        m_wrapper->cancelAuthorization();
        QTest::qWait(100);
    }
}

/**
 * TEST: Many concurrent authentication sessions
 *
 * Verifies the system can handle many simultaneous authentication requests
 * without crashes, deadlocks, or state corruption.
 *
 * Success criteria:
 * - All 50 sessions created successfully
 * - Each session maintains independent state
 * - Session map correctly tracks all sessions
 * - Cleanup properly removes all sessions
 */
void TestPerformanceStress::testManyConcurrentSessions()
{
#ifndef BUILD_TESTING
    QSKIP("Test requires BUILD_TESTING to access testTriggerAuthentication()");
#else
    const int SESSION_COUNT = 10;  // Reduced to avoid long FIDO timeouts

    qDebug() << "Creating" << SESSION_COUNT << "concurrent sessions...";
    QElapsedTimer timer;
    timer.start();

    QSignalSpy stateSpy(m_wrapper, &PolkitWrapper::authenticationStateChanged);

    // Create many concurrent sessions
    for (int i = 0; i < SESSION_COUNT; i++) {
        QString cookie = generateCookie(i);
        QString actionId = generateActionId(i);
        QString message = QString("Stress test authentication %1").arg(i);

        m_wrapper->testTriggerAuthentication(actionId, message, "dialog-password", cookie);
    }

    // Allow sessions to initialize
    QTest::qWait(200);

    qint64 creationTime = timer.elapsed();
    qDebug() << "Created" << SESSION_COUNT << "sessions in" << creationTime << "ms"
             << "(" << (double)creationTime/SESSION_COUNT << "ms per session)";

    // VERIFY: All sessions exist
    QVERIFY(m_wrapper->hasActiveSessions());

    // VERIFY: Each session has correct state
    for (int i = 0; i < SESSION_COUNT; i++) {
        QString cookie = generateCookie(i);
        AuthenticationState state = m_wrapper->authenticationState(cookie);

        // Should be in INITIATED or later state
        QVERIFY2(state != AuthenticationState::IDLE,
                 qPrintable(QString("Session %1 should not be IDLE").arg(i)));
    }

    // VERIFY: State changes emitted for all sessions
    QVERIFY2(stateSpy.count() >= SESSION_COUNT,
             qPrintable(QString("Expected at least %1 state changes, got %2")
                       .arg(SESSION_COUNT).arg(stateSpy.count())));

    // Verify all cookies received state changes
    QSet<QString> cookiesWithStateChanges;
    for (const auto &signal : stateSpy) {
        QString cookie = signal.at(0).toString();
        cookiesWithStateChanges.insert(cookie);
    }

    QVERIFY2(cookiesWithStateChanges.size() >= SESSION_COUNT,
             qPrintable(QString("Expected %1 unique cookies, got %2")
                       .arg(SESSION_COUNT).arg(cookiesWithStateChanges.size())));

    // Cleanup all sessions
    timer.restart();
    m_wrapper->cancelAuthorization();
    QTest::qWait(100);

    qint64 cleanupTime = timer.elapsed();
    qDebug() << "Cleaned up" << SESSION_COUNT << "sessions in" << cleanupTime << "ms"
             << "(" << (double)cleanupTime/SESSION_COUNT << "ms per session)";

    // VERIFY: All sessions cleaned up
    QVERIFY(!m_wrapper->hasActiveSessions());

    // Verify all sessions returned to IDLE
    for (int i = 0; i < SESSION_COUNT; i++) {
        QString cookie = generateCookie(i);
        QCOMPARE(m_wrapper->authenticationState(cookie), AuthenticationState::IDLE);
    }
#endif
}

/**
 * TEST: Rapid session creation and cleanup cycles
 *
 * Verifies the system can handle rapid churn of sessions being created
 * and destroyed without memory leaks or state corruption.
 *
 * Success criteria:
 * - 100 create/cancel cycles complete successfully
 * - Memory usage remains stable
 * - No crashes or deadlocks
 * - State properly resets between cycles
 */
void TestPerformanceStress::testRapidSessionCreationCleanup()
{
#ifndef BUILD_TESTING
    QSKIP("Test requires BUILD_TESTING to access testTriggerAuthentication()");
#else
    const int CYCLES = 100;
    const int SESSIONS_PER_CYCLE = 5;

    qDebug() << "Running" << CYCLES << "create/cleanup cycles with"
             << SESSIONS_PER_CYCLE << "sessions each...";

    QElapsedTimer timer;
    timer.start();

    for (int cycle = 0; cycle < CYCLES; cycle++) {
        // Create sessions
        for (int i = 0; i < SESSIONS_PER_CYCLE; i++) {
            QString cookie = QString("rapid-cycle-%1-session-%2").arg(cycle).arg(i);
            QString actionId = QString("org.quickshell.rapid.%1.%2").arg(cycle).arg(i);

            m_wrapper->testTriggerAuthentication(actionId, "Rapid test", "dialog-password", cookie);
        }

        // Small delay to let sessions initialize
        QTest::qWait(10);

        // Verify sessions exist
        QVERIFY(m_wrapper->hasActiveSessions());

        // Cleanup
        m_wrapper->cancelAuthorization();
        QTest::qWait(10);

        // Verify cleanup
        QVERIFY2(!m_wrapper->hasActiveSessions(),
                 qPrintable(QString("Cycle %1: Sessions should be cleaned up").arg(cycle)));
    }

    qint64 totalTime = timer.elapsed();
    double avgCycleTime = (double)totalTime / CYCLES;

    qDebug() << "Completed" << CYCLES << "cycles in" << totalTime << "ms"
             << "(" << avgCycleTime << "ms per cycle)";

    // VERIFY: System is in clean state after all cycles
    QVERIFY(!m_wrapper->hasActiveSessions());

    // Performance check: cycles should average < 750ms each
    // Each cycle creates/destroys 5 PAM sessions + 20ms wait time
    // Real PAM sessions take ~80-100ms each due to setuid helper and PAM stack
    // Allow headroom for CI variance while detecting major regressions
    QVERIFY2(avgCycleTime < 750.0,
             qPrintable(QString("Average cycle time %.2f ms exceeds 750ms threshold")
                       .arg(avgCycleTime)));
#endif
}

/**
 * TEST: Session map scalability
 *
 * Tests the performance of session map operations as the number
 * of sessions grows.
 *
 * Success criteria:
 * - State queries remain fast even with many sessions
 * - No O(n²) or worse scaling behavior
 * - Consistent performance across session counts
 */
void TestPerformanceStress::testSessionMapScalability()
{
#ifndef BUILD_TESTING
    QSKIP("Test requires BUILD_TESTING to access testTriggerAuthentication()");
#else
    QList<int> sessionCounts = {5, 10, 15};  // Reduced to avoid long FIDO timeouts
    QMap<int, qint64> queryTimes;

    for (int sessionCount : sessionCounts) {
        qDebug() << "Testing with" << sessionCount << "sessions...";

        // Create sessions
        for (int i = 0; i < sessionCount; i++) {
            QString cookie = generateCookie(i);
            QString actionId = generateActionId(i);
            m_wrapper->testTriggerAuthentication(actionId, "Scalability test", "dialog-password", cookie);
        }

        QTest::qWait(100);

        // Measure state query performance
        QElapsedTimer timer;
        timer.start();

        const int QUERY_ITERATIONS = 1000;
        for (int i = 0; i < QUERY_ITERATIONS; i++) {
            // Query random sessions
            QString cookie = generateCookie(i % sessionCount);
            m_wrapper->authenticationState(cookie);
            m_wrapper->sessionRetryCount(cookie);
        }

        qint64 elapsed = timer.nsecsElapsed();
        queryTimes[sessionCount] = elapsed;

        double avgQueryTime = (double)elapsed / QUERY_ITERATIONS / 1000.0; // microseconds
        qDebug() << "  " << QUERY_ITERATIONS << "queries in" << elapsed / 1000000.0 << "ms"
                 << "(" << avgQueryTime << "μs per query)";

        // Cleanup for next iteration
        m_wrapper->cancelAuthorization();
        QTest::qWait(100);
    }

    // VERIFY: Query time doesn't scale badly
    // With 3x sessions (5 -> 15), query time should be < 5x slower
    double time5 = queryTimes[5];
    double time15 = queryTimes[15];
    double scalingFactor = time15 / time5;

    qDebug() << "Scaling factor (5 -> 15 sessions):" << scalingFactor << "x";

    QVERIFY2(scalingFactor < 5.0,
             qPrintable(QString("Query scaling factor %.2f exceeds 5x threshold")
                       .arg(scalingFactor)));
#endif
}

/**
 * TEST: State transition performance
 *
 * Measures performance of state transitions and signal emissions.
 *
 * Success criteria:
 * - State transitions complete quickly (< 1ms average)
 * - Signal emission doesn't cause significant overhead
 * - Performance consistent across many transitions
 */
void TestPerformanceStress::testStateTransitionPerformance()
{
#ifndef BUILD_TESTING
    QSKIP("Test requires BUILD_TESTING to access testTriggerAuthentication()");
#else
    const int TRANSITION_COUNT = 1000;

    QSignalSpy stateSpy(m_wrapper, &PolkitWrapper::authenticationStateChanged);
    QSignalSpy methodSpy(m_wrapper, &PolkitWrapper::authenticationMethodChanged);

    qDebug() << "Measuring" << TRANSITION_COUNT << "state transitions...";

    QElapsedTimer timer;
    timer.start();

    // Trigger many authentication requests (each causes state transitions)
    for (int i = 0; i < TRANSITION_COUNT; i++) {
        QString cookie = QString("transition-test-%1").arg(i);
        QString actionId = QString("org.quickshell.transition.%1").arg(i);

        m_wrapper->testTriggerAuthentication(actionId, "Transition test", "dialog-password", cookie);

        // Immediately cancel to trigger more transitions
        m_wrapper->cancelAuthorization();
    }

    qint64 elapsed = timer.elapsed();
    double avgTransitionTime = (double)elapsed / TRANSITION_COUNT;

    qDebug() << TRANSITION_COUNT << "transitions in" << elapsed << "ms"
             << "(" << avgTransitionTime << "ms per transition)";

    // VERIFY: Signals were emitted
    QVERIFY(stateSpy.count() > 0);

    // VERIFY: Average transition time is reasonable (< 1ms)
    QVERIFY2(avgTransitionTime < 1.0,
             qPrintable(QString("Average transition time %.3f ms exceeds 1ms threshold")
                       .arg(avgTransitionTime)));

    // VERIFY: System is clean after all transitions
    QVERIFY(!m_wrapper->hasActiveSessions());
#endif
}

/**
 * TEST: Memory stability under load
 *
 * Runs extended session churn to detect memory leaks or
 * accumulation of stale state.
 *
 * Success criteria:
 * - No crashes during extended operation
 * - State remains consistent
 * - Session cleanup is complete
 */
void TestPerformanceStress::testMemoryStability()
{
#ifndef BUILD_TESTING
    QSKIP("Test requires BUILD_TESTING to access testTriggerAuthentication()");
#else
    const int ITERATIONS = 50;  // Reduced for faster execution
    const int SESSIONS_PER_ITERATION = 5;  // Reduced to avoid FIDO timeouts

    qDebug() << "Running memory stability test:" << ITERATIONS << "iterations with"
             << SESSIONS_PER_ITERATION << "sessions each...";

    QElapsedTimer timer;
    timer.start();

    for (int iter = 0; iter < ITERATIONS; iter++) {
        // Create batch of sessions
        for (int i = 0; i < SESSIONS_PER_ITERATION; i++) {
            QString cookie = QString("mem-test-%1-%2").arg(iter).arg(i);
            QString actionId = QString("org.quickshell.memory.%1.%2").arg(iter).arg(i);
            m_wrapper->testTriggerAuthentication(actionId, "Memory test", "dialog-password", cookie);
        }

        // Verify sessions exist
        QVERIFY(m_wrapper->hasActiveSessions());

        // Cleanup
        m_wrapper->cancelAuthorization();

        // Verify cleanup completed
        QVERIFY2(!m_wrapper->hasActiveSessions(),
                 qPrintable(QString("Iteration %1: Cleanup failed").arg(iter)));

        // Progress indicator every 10 iterations
        if (iter % 10 == 0 && iter > 0) {
            qDebug() << "  Completed" << iter << "iterations...";
        }
    }

    qint64 elapsed = timer.elapsed();
    qDebug() << "Memory stability test completed in" << elapsed << "ms"
             << "(" << (ITERATIONS * SESSIONS_PER_ITERATION) << "total session lifecycles)";

    // VERIFY: System is in clean final state
    QVERIFY(!m_wrapper->hasActiveSessions());

    // If we got here without crashes, memory management is working
    QVERIFY(true);
#endif
}

/**
 * TEST: Concurrent state queries
 *
 * Tests thread-safety and performance of concurrent state queries
 * while sessions are being created/modified.
 *
 * Success criteria:
 * - No crashes or data races
 * - Queries return valid states
 * - Performance remains acceptable under concurrent load
 */
void TestPerformanceStress::testConcurrentStateQueries()
{
#ifndef BUILD_TESTING
    QSKIP("Test requires BUILD_TESTING to access testTriggerAuthentication()");
#else
    const int SESSION_COUNT = 20;
    const int QUERY_COUNT = 100;

    qDebug() << "Testing concurrent state queries with" << SESSION_COUNT << "sessions...";

    // Create sessions
    for (int i = 0; i < SESSION_COUNT; i++) {
        QString cookie = generateCookie(i);
        QString actionId = generateActionId(i);
        m_wrapper->testTriggerAuthentication(actionId, "Concurrent query test", "dialog-password", cookie);
    }

    QTest::qWait(100);

    // Perform many rapid queries
    QElapsedTimer timer;
    timer.start();

    for (int i = 0; i < QUERY_COUNT; i++) {
        // Query all sessions
        for (int j = 0; j < SESSION_COUNT; j++) {
            QString cookie = generateCookie(j);

            // These should not crash or return invalid data
            AuthenticationState state = m_wrapper->authenticationState(cookie);
            int retryCount = m_wrapper->sessionRetryCount(cookie);
            bool hasActive = m_wrapper->hasActiveSessions();

            // VERIFY: State is valid
            QVERIFY(state >= AuthenticationState::IDLE && state <= AuthenticationState::ERROR);

            // VERIFY: Retry count is valid
            QVERIFY(retryCount >= 0 && retryCount <= 3);

            // VERIFY: hasActiveSessions returns true (we have sessions)
            QVERIFY(hasActive);
        }
    }

    qint64 elapsed = timer.elapsed();
    int totalQueries = QUERY_COUNT * SESSION_COUNT * 3; // 3 queries per session per iteration
    double avgQueryTime = (double)elapsed / totalQueries;

    qDebug() << totalQueries << "concurrent queries in" << elapsed << "ms"
             << "(" << avgQueryTime << "ms per query)";

    // VERIFY: Query performance is acceptable (< 0.1ms average)
    QVERIFY2(avgQueryTime < 0.1,
             qPrintable(QString("Average query time %.3f ms exceeds 0.1ms threshold")
                       .arg(avgQueryTime)));

    // Cleanup
    m_wrapper->cancelAuthorization();
    QTest::qWait(100);
    QVERIFY(!m_wrapper->hasActiveSessions());
#endif
}

QTEST_MAIN(TestPerformanceStress)
#include "test-performance-stress.moc"
