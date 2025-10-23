/*
 * Test helper for triggering polkit authentication flows
 *
 * Simulates polkit daemon calling our agent's initiateAuthentication()
 */

#pragma once

#include <QObject>
#include <QString>
#include <polkitqt1-agent-session.h>
#include <polkitqt1-identity.h>
#include <polkitqt1-details.h>
#include "../src/polkit-wrapper.h"
#include <unistd.h>

/*
 * Helper to create test identities
 */
class PolkitTestHelper
{
public:
    /*
     * Create identity for current user
     *
     * This is what polkit would pass to initiateAuthentication()
     */
    static PolkitQt1::Identity createTestIdentity()
    {
        // Use current user's UID
        uid_t uid = getuid();
        return PolkitQt1::UnixUserIdentity(uid);
    }

    /*
     * Create test details
     *
     * Simulates the "details" dictionary polkit passes
     */
    static PolkitQt1::Details createTestDetails()
    {
        PolkitQt1::Details details;
        // Empty details for basic tests
        return details;
    }

    /*
     * Trigger authentication for testing
     *
     * NOTE: This helper is deprecated. Use PolkitWrapper::testTriggerAuthentication()
     * directly instead, which is available when BUILD_TESTING is defined.
     *
     * See: src/polkit-wrapper.h testTriggerAuthentication() method
     */
    static void triggerAuthentication(
        PolkitWrapper *wrapper,
        const QString &actionId,
        const QString &message,
        const QString &iconName,
        const QString &cookie)
    {
#ifdef BUILD_TESTING
        wrapper->testTriggerAuthentication(actionId, message, iconName, cookie);
#else
        qWarning() << "testTriggerAuthentication() only available when BUILD_TESTING is defined";
#endif
    }
};
