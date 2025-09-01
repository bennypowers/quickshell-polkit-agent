# Logging Configuration

This application uses Qt's logging categories for different types of debug output.

## Available Categories

- `polkit.agent` - General polkit agent operations
- `polkit.sensitive` - Sensitive authentication cookie information (disabled by default)
- `ipc.server` - IPC server communication 
- `ipc.file` - File-based IPC operations

## Configuration

### Runtime Configuration

Use Qt's `QT_LOGGING_RULES` environment variable:

```bash
# Enable all logging
export QT_LOGGING_RULES="*=true"

# Enable only specific categories
export QT_LOGGING_RULES="polkit.agent=true;ipc.server=true"

# Enable sensitive cookie logging (security risk)
export QT_LOGGING_RULES="polkit.sensitive=true"

# Disable all logging
export QT_LOGGING_RULES="*=false"
```

### Configuration Files

You can also create a persistent configuration file:

```bash
# System-wide configuration
echo "polkit.agent=true" > /etc/qt6/qtlogging.ini

# User configuration  
mkdir -p ~/.config/QtProject
echo "polkit.agent=true" > ~/.config/QtProject/qtlogging.ini
```

## Security Note

The `polkit.sensitive` category logs authentication cookies which are security-sensitive.
Only enable this category for debugging purposes and never in production environments.

## Examples

```bash
# Debug IPC issues
QT_LOGGING_RULES="ipc.*=true" quickshell-polkit-agent

# Debug polkit operations (safe)
QT_LOGGING_RULES="polkit.agent=true" quickshell-polkit-agent

# Full debugging (includes sensitive data)
QT_LOGGING_RULES="*=true" quickshell-polkit-agent
```