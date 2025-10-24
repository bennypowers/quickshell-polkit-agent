/*
 * Mock PAM module for testing FIDO/U2F authentication flows
 *
 * This module simulates FIDO authentication behavior for testing without
 * requiring physical hardware. Behavior is controlled via environment variables.
 *
 * Environment Variables:
 *   FIDO_TEST_MODE=success  - Simulate successful FIDO auth
 *   FIDO_TEST_MODE=timeout  - Simulate FIDO timeout (>15s)
 *   FIDO_TEST_MODE=fail     - Simulate FIDO failure
 *   FIDO_TEST_DELAY=<ms>    - Delay before response (default: 1000ms)
 *
 * Build:
 *   gcc -fPIC -shared -o pam_fido_mock.so pam_fido_mock.c -lpam
 *
 * Usage in PAM config:
 *   auth required pam_fido_mock.so
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

/* Simulate FIDO device wait */
static void simulate_fido_wait(pam_handle_t *pamh, int delay_ms)
{
    /* Clamp delay to sane range for tests */
    if (delay_ms < 0) delay_ms = 0;
    if (delay_ms > 60000) delay_ms = 60000;  /* cap at 60s */

    pam_syslog(pamh, LOG_INFO, "pam_fido_mock: Simulating FIDO device wait (%dms)", delay_ms);
    usleep(delay_ms * 1000);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    const char *mode = getenv("FIDO_TEST_MODE");
    const char *delay_str = getenv("FIDO_TEST_DELAY");
    int delay_ms = delay_str ? atoi(delay_str) : 1000;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    int retval;

    pam_syslog(pamh, LOG_INFO, "pam_fido_mock: Starting FIDO authentication simulation");
    pam_syslog(pamh, LOG_INFO, "pam_fido_mock: Mode=%s, Delay=%dms",
               mode ? mode : "default", delay_ms);

    /* Default mode: quick failure (FIDO not available) */
    if (!mode || strlen(mode) == 0) {
        mode = "fail";
    }

    /* Get the conversation function to trigger PolkitWrapper::request() */
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS || !conv || !conv->conv) {
        pam_syslog(pamh, LOG_ERR, "pam_fido_mock: Failed to get conversation function");
        return PAM_SYSTEM_ERR;
    }

    /* Send a prompt to trigger the agent's request() handler */
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "FIDO/U2F authentication (tap security key):";

    pam_syslog(pamh, LOG_INFO, "pam_fido_mock: Calling conversation function to trigger request()");
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);

    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "pam_fido_mock: Conversation failed: %d", retval);
        return PAM_AUTH_ERR;
    }

    /* Free the response if provided */
    if (resp) {
        if (resp->resp) {
            memset(resp->resp, 0, strlen(resp->resp));
            free(resp->resp);
        }
        free(resp);
    }

    if (strcmp(mode, "success") == 0) {
        /* Simulate successful FIDO authentication */
        simulate_fido_wait(pamh, delay_ms);
        pam_syslog(pamh, LOG_INFO, "pam_fido_mock: FIDO authentication SUCCEEDED");
        return PAM_SUCCESS;

    } else if (strcmp(mode, "timeout") == 0) {
        /* Simulate FIDO timeout (exceed agent's 15s timeout) */
        pam_syslog(pamh, LOG_INFO, "pam_fido_mock: Simulating FIDO timeout");
        sleep(16);  /* Exceed 15 second timeout */
        pam_syslog(pamh, LOG_INFO, "pam_fido_mock: FIDO authentication TIMED OUT");
        return PAM_AUTH_ERR;

    } else if (strcmp(mode, "fail") == 0) {
        /* Simulate FIDO failure (device present but auth failed) */
        simulate_fido_wait(pamh, delay_ms);
        pam_syslog(pamh, LOG_INFO, "pam_fido_mock: FIDO authentication FAILED");
        return PAM_AUTH_ERR;

    } else if (strcmp(mode, "unavailable") == 0) {
        /* Simulate FIDO device not available (immediate failure) */
        pam_syslog(pamh, LOG_INFO, "pam_fido_mock: FIDO device UNAVAILABLE");
        return PAM_AUTHINFO_UNAVAIL;

    } else {
        pam_syslog(pamh, LOG_ERR, "pam_fido_mock: Unknown mode '%s'", mode);
        return PAM_AUTH_ERR;
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    /* No credentials to set for FIDO */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    return PAM_SUCCESS;
}
