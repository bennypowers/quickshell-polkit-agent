/*
 * Helper program to trigger polkit authorization requests for E2E testing
 *
 * This triggers real authorization via polkitd, which will call our agent's
 * initiateAuthentication() method, allowing genuine E2E testing.
 */

#include <QCoreApplication>
#include <QDebug>
#include <polkitqt1-authority.h>
#include <polkitqt1-subject.h>
#include <QTimer>
#include <unistd.h>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    if (argc < 2) {
        qWarning() << "Usage:" << argv[0] << "<action-id>";
        qWarning() << "Example:" << argv[0] << "org.quickshell.polkit.test.auth-required";
        return 1;
    }

    QString actionId = argv[1];
    qDebug() << "Triggering polkit authorization for action:" << actionId;

    // Get polkit authority
    PolkitQt1::Authority *authority = PolkitQt1::Authority::instance();

    // Create subject for current process
    PolkitQt1::UnixProcessSubject subject(getpid());

    // Start async authorization check
    // This will cause polkitd to call the registered agent's initiateAuthentication()
    PolkitQt1::Authority::Result result = authority->checkAuthorizationSync(
        actionId,
        subject,
        PolkitQt1::Authority::AllowUserInteraction
    );

    // Print result
    switch (result) {
        case PolkitQt1::Authority::Yes:
            qDebug() << "Authorization GRANTED";
            return 0;
        case PolkitQt1::Authority::No:
            qDebug() << "Authorization DENIED";
            return 1;
        case PolkitQt1::Authority::Challenge:
            qDebug() << "Authorization CHALLENGE (should not happen with sync)";
            return 2;
        default:
            qDebug() << "Authorization UNKNOWN";
            return 3;
    }
}
