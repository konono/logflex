
# LogFlex

LogFlex is a flexible and powerful logging extension for Python applications, enhancing the built-in logging capabilities with advanced configuration options and support for multiple output handlers.

## Features

- **Customizable Log Levels**: Set different log levels for different output handlers.
- **File and Console Logging**: Easily log to files and the console with simple configuration.
- **Syslog Integration**: Send logs to a Syslog server for centralized logging.
- **Colorized Output**: Make console output more readable with customizable colorization.
- **Automatic File Rotation**: Rotate log files based on time or size automatically.

## Installation

Install LogFlex using pip:

```
pip install logflex
```

## Configuration

LogFlex uses a combination of a TOML configuration file and environment variables to customize its behavior. Here is how you can set up your logging:

### Config File (`config.toml`)

Create a `config.toml` in your project root or specify its path during logger initialization. Here's an example configuration:

```toml
[general]
log_level = "DEBUG"
verbose = false
trace = false

[general.color_settings]
enable_color = true
datefmt = "%Y-%m-%d %H:%M:%S"
reset = true
log_colors.DEBUG = "cyan"
log_colors.INFO = "green"
log_colors.WARNING = "yellow"
log_colors.ERROR = "red"
log_colors.CRITICAL = "red,bg_white"
style = "%"

[file_handler]
logdir = "./logs"
logfile = "app.log"
dedicate_error_logfile = true

[syslog_handler]
use_syslog = true
syslog_address = "localhost"
syslog_port = 514 # UDP Port
syslog_facility = 'LOG_USER'
```

### Environment Variables

You can also configure LogFlex using environment variables, which override the settings from `config.toml`. Here are some of the variables you can set:

```
GENERAL_LOG_LEVEL=DEBUG
GENERAL_VERBOSE=false
GENERAL_TRACE=false
FILEHANDLER_LOGDIR=/var/log/myapp
FILEHANDLER_LOGFILE=app.log
SYSLOGHANDLER_USE_SYSLOG=true
SYSLOGHANDLER_SYSLOG_ADDRESS=localhost
SYSLOGHANDLER_SYSLOG_PORT=514
COLOR_ENABLE_COLOR=true
COLOR_DATEFMT="%Y-%m-%d %H:%M:%S"
COLOR_RESET=true
COLOR_LOG_COLORS_DEBUG="cyan"
COLOR_LOG_COLORS_INFO="green"
COLOR_LOG_COLORS_WARNING="yellow"
COLOR_LOG_COLORS_ERROR="red"
COLOR_LOG_COLORS_CRITICAL="red,bg_white"
COLOR_STYLE="%"
FILEHANDLER_LOGDIR="./logs"
FILEHANDLER_LOGFILE="app.log"
FILEHANDLER_WHEN='midnight'
FILEHANDLER_INTERVAL=7
FILEHANDLER_BACKUP_COUNT=7
FILEHANDLER_DEDICATE_ERROR_LOGFILE=true
SYSLOGHANDLER_USE_SYSLOG=true
SYSLOGHANDLER_SYSLOG_ADDRESS='localhost'
SYSLOGHANDLER_SYSLOG_PORT=514
SYSLOGHANDLER_SYSLOG_FACILITY='LOG_USER'
```

## Usage

### Basic Setup

```python
from logflex import CustomLogger

# Initialize logger with default settings
logger = CustomLogger('exampleModule', loglevel='INFO')

# Write logs
logger.info("This is an info message")
logger.error("This is an error message")
```

### Using Stream Handler

```python
from logflex import CustomLogger

# Initialize logger for console output with debug level
logger = CustomLogger('exampleModule', loglevel='DEBUG', verbose=true, trace=False, color_enable=true)

# Console output
logger.debug("This message will appear in the console.")
```

### Using File Handler

```python
from logflex import CustomLogger

# Initialize logger with file output
logger = CustomLogger('exampleModule', loglevel='WARNING', file_logdir='./log', file_logfile='app.log',
                      file_when='midnight', file_interval=7, file_backup_count=7, file_dedicate_error_logfile=False)

logger.warning("This message will be logged to a file.")
```

### Using Syslog Handler

```python
from logflex import CustomLogger

# Initialize logger with Syslog handler
logger = CustomLogger('exampleModule', loglevel='CRITICAL', use_syslog=true, syslog_address='localhost', syslog_port=514,
                      syslog_facility='LOG_LOCAL0')


# Syslog output
logger.critical("This critical message will be sent to the configured Syslog server.")
```

## Contributing

Contributions to LogFlex are welcome! Please fork the repository and submit a pull request with your changes or improvements.

## License

LogFlex is released under the MIT License. See the LICENSE file for more details.

## Support

For support, please open an issue on the GitHub repository or contact the maintainers directly.
