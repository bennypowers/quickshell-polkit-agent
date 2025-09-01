#include "logging.h"

// Define logging categories
Q_LOGGING_CATEGORY(polkitAgent, "polkit.agent")
Q_LOGGING_CATEGORY(polkitSensitive, "polkit.sensitive") // Disabled by default for security
Q_LOGGING_CATEGORY(ipcServer, "ipc.server")
Q_LOGGING_CATEGORY(fileIpc, "ipc.file")