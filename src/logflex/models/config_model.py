#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging.handlers import SysLogHandler
from dataclasses import dataclass, field
from typing import Optional, Dict


FACILITY_MAP = {
    'LOG_KERN': SysLogHandler.LOG_KERN,
    'LOG_USER': SysLogHandler.LOG_USER,
    'LOG_MAIL': SysLogHandler.LOG_MAIL,
    'LOG_DAEMON': SysLogHandler.LOG_DAEMON,
    'LOG_AUTH': SysLogHandler.LOG_AUTH,
    'LOG_SYSLOG': SysLogHandler.LOG_SYSLOG,
    'LOG_LPR': SysLogHandler.LOG_LPR,
    'LOG_NEWS': SysLogHandler.LOG_NEWS,
    'LOG_UUCP': SysLogHandler.LOG_UUCP,
    'LOG_CRON': SysLogHandler.LOG_CRON,
    'LOG_AUTHPRIV': SysLogHandler.LOG_AUTHPRIV,
    'LOG_FTP': SysLogHandler.LOG_FTP,
    'LOG_NTP': SysLogHandler.LOG_NTP,
    'LOG_SECURITY': SysLogHandler.LOG_SECURITY,
    'LOG_CONSOLE': SysLogHandler.LOG_CONSOLE,
    'LOG_LOCAL0': SysLogHandler.LOG_LOCAL0,
    'LOG_LOCAL1': SysLogHandler.LOG_LOCAL1,
    'LOG_LOCAL2': SysLogHandler.LOG_LOCAL2,
    'LOG_LOCAL3': SysLogHandler.LOG_LOCAL3,
    'LOG_LOCAL4': SysLogHandler.LOG_LOCAL4,
    'LOG_LOCAL5': SysLogHandler.LOG_LOCAL5,
    'LOG_LOCAL6': SysLogHandler.LOG_LOCAL6,
    'LOG_LOCAL7': SysLogHandler.LOG_LOCAL7
}


@dataclass
class ColorSettings:
    enable_color: bool = False
    datefmt: Optional[str] = None
    reset: bool = True
    log_colors: Dict[str, str] = field(default_factory=dict)
    secondary_log_colors: Dict[str, str] = field(default_factory=dict)
    style: str = '%'

    @staticmethod
    def env_keys():
        return {
            'enable_color': 'COLOR_ENABLE_COLOR',
            'datefmt': 'COLOR_DATEFMT',
            'reset': 'COLOR_RESET',
            'log_colors': {
                'DEBUG': 'COLOR_LOG_COLORS_DEBUG',
                'INFO': 'COLOR_LOG_COLORS_INFO',
                'WARNING': 'COLOR_LOG_COLORS_WARNING',
                'ERROR': 'COLOR_LOG_COLORS_ERROR',
                'CRITICAL': 'COLOR_LOG_COLORS_CRITICAL'
            },
            'style': 'COLOR_STYLE'
        }

@dataclass
class GeneralSettings:
    log_level: str = 'INFO'
    verbose: bool = False
    trace: bool = False
    format: Optional[str]= None
    color_settings: ColorSettings = field(default_factory=ColorSettings)
    enable_dynamic_reloading: bool = False

    @staticmethod
    def env_keys():
        return {
            'log_level': 'GENERAL_LOG_LEVEL',
            'verbose': 'GENERAL_VERBOSE',
            'trace': 'GENERAL_TRACE',
            'format': 'GENERAL_FORMAT',
            'color_settings': ColorSettings.env_keys(),
            'enable_dynamic_reloading': False
        }

@dataclass
class FileHandlerSettings:
    logdir: Optional[str] = None
    logfile: Optional[str] = None
    when: str = 'midnight'
    interval: int = 1
    backup_count: int = 7
    dedicate_error_logfile: bool = False
    color_settings: ColorSettings = field(default_factory=ColorSettings)

    @staticmethod
    def env_keys():
        return {
            'logdir': 'FILEHANDLER_LOGDIR',
            'logfile': 'FILEHANDLER_LOGFILE',
            'when': 'FILEHANDLER_WHEN',
            'interval': 'FILEHANDLER_INTERVAL',
            'backup_count': 'FILEHANDLER_BACKUP_COUNT',
            'color_settings': ColorSettings.env_keys(),
            'dedicate_error_logfile': 'FILEHANDLER_DEDICATE_ERROR_LOGFILE'
        }

@dataclass
class SyslogHandlerSettings:
    use_syslog: bool = False
    syslog_address: str = 'localhost'
    syslog_port: int = 514
    syslog_facility: str = 'LOG_USER'

    @staticmethod
    def env_keys():
        return {
            'use_syslog': 'SYSLOGHANDLER_USE_SYSLOG',
            'syslog_address': 'SYSLOGHANDLER_SYSLOG_ADDRESS',
            'syslog_port': 'SYSLOGHANDLER_SYSLOG_PORT',
            'syslog_facility': 'SYSLOGHANDLER_SYSLOG_FACILITY',
        }

@dataclass
class Configuration:
    general: GeneralSettings
    file_handler: FileHandlerSettings
    syslog_handler: SyslogHandlerSettings
