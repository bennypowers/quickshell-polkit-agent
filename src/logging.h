#pragma once

#include <QLoggingCategory>

// Logging categories for different components
Q_DECLARE_LOGGING_CATEGORY(polkitAgent)
Q_DECLARE_LOGGING_CATEGORY(polkitSensitive) // For sensitive auth cookie logs
Q_DECLARE_LOGGING_CATEGORY(ipcServer)
Q_DECLARE_LOGGING_CATEGORY(fileIpc)