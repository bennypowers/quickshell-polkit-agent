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
    // Force unbuffered stderr
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "trigger-polkit-action: Starting (PID: %d)\n", getpid());
    fflush(stderr);

    QCoreApplication app(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <action-id>\n", argv[0]);
        fprintf(stderr, "Example: %s org.quickshell.polkit.test.auth-required\n", argv[0]);
        return 1;
    }

    QString actionId = argv[1];
    fprintf(stderr, "trigger-polkit-action: Action ID: %s\n", qPrintable(actionId));
    fflush(stderr);

    // Get polkit authority
    PolkitQt1::Authority *authority = PolkitQt1::Authority::instance();
    fprintf(stderr, "trigger-polkit-action: Authority instance obtained\n");
    fflush(stderr);

    // Create subject for current process
    PolkitQt1::UnixProcessSubject subject(getpid());
    fprintf(stderr, "trigger-polkit-action: Created UnixProcessSubject for PID %d\n", getpid());
    fflush(stderr);

    // Set up signal handlers for authorization result
    int exitCode = 3; // Default: unknown

    // Handle completion
    QObject::connect(authority, &PolkitQt1::Authority::checkAuthorizationFinished,
                     [&exitCode, &app](PolkitQt1::Authority::Result result) {
        fprintf(stderr, "trigger-polkit-action: checkAuthorizationFinished signal received\n");
        fflush(stderr);

        switch (result) {
            case PolkitQt1::Authority::Yes:
                fprintf(stderr, "trigger-polkit-action: Authorization GRANTED\n");
                exitCode = 0;
                break;
            case PolkitQt1::Authority::No:
                fprintf(stderr, "trigger-polkit-action: Authorization DENIED\n");
                exitCode = 1;
                break;
            case PolkitQt1::Authority::Challenge:
                fprintf(stderr, "trigger-polkit-action: Authorization CHALLENGE (authentication required but failed)\n");
                exitCode = 2;
                break;
            default:
                fprintf(stderr, "trigger-polkit-action: Authorization UNKNOWN\n");
                exitCode = 3;
                break;
        }
        fflush(stderr);
        app.quit();
    });

    // Timeout after 60 seconds if no response
    QTimer::singleShot(60000, &app, [&app, &exitCode]() {
        fprintf(stderr, "trigger-polkit-action: Timeout waiting for authorization\n");
        fflush(stderr);
        exitCode = 4;
        app.quit();
    });

    // Start async authorization check
    // This will cause polkitd to call the registered agent's initiateAuthentication()
    fprintf(stderr, "trigger-polkit-action: Calling checkAuthorization (async)...\n");
    fflush(stderr);

    authority->checkAuthorization(
        actionId,
        subject,
        PolkitQt1::Authority::AllowUserInteraction
    );

    fprintf(stderr, "trigger-polkit-action: checkAuthorization called, waiting for result...\n");
    fflush(stderr);

    // Run event loop to wait for authorization result
    app.exec();

    fprintf(stderr, "trigger-polkit-action: Exiting with code %d\n", exitCode);
    fflush(stderr);
    return exitCode;
}
