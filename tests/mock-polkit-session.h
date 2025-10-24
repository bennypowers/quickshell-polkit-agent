/*
 * Mock PolkitQt1::Agent::Session for testing
 *
 * Allows tests to control PAM responses without real authentication
 */

#pragma once

#include <QObject>
#include <QString>
#include <QTimer>
#include <polkitqt1-agent-session.h>
#include <polkitqt1-identity.h>

/*
 * MockPolkitSession - Test double for PolkitQt1::Agent::Session
 *
 * Simulates PAM conversation flow for testing:
 * 1. initiate() starts authentication
 * 2. Emits request() signal for password
 * 3. setResponse() receives user input
 * 4. Emits completed() with success/failure
 *
 * Test can control behavior with simulateSuccess/simulateFailure
 */
class MockPolkitSession : public QObject
{
    Q_OBJECT

public:
    explicit MockPolkitSession(const PolkitQt1::Identity &identity,
                              const QString &cookie,
                              QObject *parent = nullptr)
        : QObject(parent)
        , m_identity(identity)
        , m_cookie(cookie)
        , m_initiated(false)
        , m_shouldSucceed(true)
        , m_requestCount(0)
    {
    }

    // Control test behavior
    void setShouldSucceed(bool succeed) { m_shouldSucceed = succeed; }
    void setSimulateFido(bool fido) { m_simulateFido = fido; }
    void setFidoShouldSucceed(bool succeed) { m_fidoShouldSucceed = succeed; }

    // Track test state
    int requestCount() const { return m_requestCount; }
    bool isInitiated() const { return m_initiated; }
    QString cookie() const { return m_cookie; }

public slots:
    /*
     * Initiate PAM authentication (mocked)
     *
     * In real PolkitQt1::Agent::Session, this calls pam_authenticate().
     * For testing, we simulate the PAM conversation flow.
     */
    void initiate()
    {
        m_initiated = true;
        m_cancelled = false;

        // Simulate PAM conversation starting
        // Real PAM would call our conversation function, we simulate with timer
        QTimer::singleShot(50, this, [this]() {
            if (m_cancelled) return;
            if (m_simulateFido) {
                // Simulate FIDO attempt (first request with empty response expected)
                emit request("Touch your security key", false);
                m_requestCount++;
            } else {
                // Simulate password request
                emit request("Password:", false);
                m_requestCount++;
            }
        });
    }

    /*
     * Submit response to PAM (mocked)
     *
     * In real session, this goes to PAM. For testing, we decide
     * success/failure based on test configuration.
     */
    void setResponse(const QString &response)
    {
        QTimer::singleShot(50, this, [this, response]() {
            if (m_cancelled) return;
            if (m_simulateFido && response.isEmpty()) {
                // Empty response for FIDO attempt
                if (m_fidoShouldSucceed) {
                    // FIDO succeeded
                    emit completed(true);
                } else {
                    // FIDO failed, ask for password
                    m_simulateFido = false;  // Switch to password mode
                    emit request("Password:", false);
                    m_requestCount++;
                }
            } else {
                // Password response
                emit completed(m_shouldSucceed);
            }
        });
    }

    void cancel()
    {
        m_cancelled = true;
        if (!m_initiated) return;
        // Simulate cancellation
        emit completed(false);
    }

signals:
    /*
     * Signals matching PolkitQt1::Agent::Session interface
     */
    void completed(bool gainedAuthorization);
    void request(const QString &request, bool echo);
    void showError(const QString &text);
    void showInfo(const QString &text);

private:
    PolkitQt1::Identity m_identity;
    QString m_cookie;
    bool m_initiated;
    bool m_shouldSucceed;
    bool m_simulateFido = false;
    bool m_fidoShouldSucceed = false;
    int m_requestCount;
    bool m_cancelled = false;
};
