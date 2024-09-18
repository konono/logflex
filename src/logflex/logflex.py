#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pathlib
import traceback
import threading

from typing import List
from logging import getLogger, StreamHandler, Formatter, Filter, ERROR, Logger
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
from colorlog import ColoredFormatter
from logflex.config.settings import ConfigLoader, ConfigBuilder
from logflex.models.config_model import FACILITY_MAP

logger_lock = threading.Lock()

def stacktrace_lines() -> List[str]:
    return [line for line in traceback.format_stack() if '/logflex/logflex.py' not in line]


class StackTraceFilter(Filter):
    def filter(self, record):
        stacktraces = ["\n  " + trace.replace("%", "%%") for trace in stacktrace_lines()]
        if stacktraces:
            record.msg = f"{record.msg}\n##### Trace ##### {''.join(stacktraces)}"
        return True


class ErrorBelowFilter(Filter):
    def filter(self, record):
        return record.levelno < ERROR


class CustomLogger:
    def __new__(cls, module: str, config_loader: ConfigLoader = None, **kwargs) -> Logger:
        if kwargs:
            config = ConfigBuilder.build_config(**kwargs)
        else:
            if config_loader is None:
                config_loader = ConfigLoader()
            config = config_loader.config

        logger = getLogger(module)
        cls.configure_logger(logger, config)

        if config_loader and config.general.enable_dynamic_reloading:
            from logflex.config.watcher import start_config_watcher
            start_config_watcher(config_loader, logger)

        return logger

    @classmethod
    def configure_logger(cls, logger: Logger, config):
        with logger_lock:
            logger.handlers.clear()

            if config.general.trace:
                logger.addFilter(StackTraceFilter())

            logger.setLevel(config.general.log_level)
            logger.propagate = False

            cls._add_handler(logger, StreamHandler, config.general, config.general)

            if config.file_handler.logdir:
                cls._add_handler(logger, TimedRotatingFileHandler, config.file_handler, config.general)

            if config.file_handler.dedicate_error_logfile:
                cls._add_error_handler(logger, config)

            if config.syslog_handler.use_syslog:
                cls._add_syslog_handler(logger, config)

    @staticmethod
    def _add_handler(logger: Logger, handler_type, handler_config, general_config, level=None, filter=None):
        if hasattr(handler_config, 'logdir'):
            pathlib.Path(handler_config.logdir).mkdir(parents=True, exist_ok=True)
            log_file_path = os.path.join(handler_config.logdir, handler_config.logfile or f"{logger.name}.log")
            handler = handler_type(
                log_file_path,
                when=handler_config.when,
                interval=handler_config.interval,
                backupCount=handler_config.backup_count
            )
        else:
            handler = handler_type()
        if level:
            handler.setLevel(level)
        if filter:
            handler.addFilter(filter)

        verbose = getattr(handler_config, 'verbose', general_config.verbose)
        format_str = getattr(handler_config, 'format', general_config.format)
        color_settings = getattr(handler_config, 'color_settings', general_config.color_settings)
        enable_color = color_settings.enable_color

        log_format = CustomLogger._create_format(verbose, format_str, enable_color)
        if enable_color:
            formatter = ColoredFormatter(
                log_format,
                datefmt=color_settings.datefmt,
                reset=color_settings.reset,
                log_colors=color_settings.log_colors,
                secondary_log_colors=color_settings.secondary_log_colors,
                style=color_settings.style
            )
        else:
            formatter = Formatter(log_format)

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    @staticmethod
    def _add_error_handler(logger, config):
        file_handler_cnf = config.file_handler
        general_cnf = config.general
        log_file_path = os.path.join(file_handler_cnf.logdir, file_handler_cnf.logfile or f"{logger.name}.log")
        error_file_path = os.path.splitext(log_file_path)[0] + "_error.log"

        handler = TimedRotatingFileHandler(
            error_file_path, when=file_handler_cnf.when,
            interval=file_handler_cnf.interval,
            backupCount=file_handler_cnf.backup_count
        )
        handler.setLevel('ERROR')

        color_settings = general_cnf.color_settings
        enable_color = color_settings.enable_color
        log_format = CustomLogger._create_format(general_cnf.verbose, general_cnf.format, enable_color)

        if enable_color:
            formatter = ColoredFormatter(
                log_format,
                datefmt=color_settings.datefmt,
                reset=color_settings.reset,
                log_colors=color_settings.log_colors,
                secondary_log_colors=color_settings.secondary_log_colors,
                style=color_settings.style
            )
        else:
            formatter = Formatter(log_format)

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    @staticmethod
    def _add_syslog_handler(logger, config):
        syslog_handler_cnf = config.syslog_handler
        general_cnf = config.general
        facility = FACILITY_MAP.get(syslog_handler_cnf.syslog_facility, SysLogHandler.LOG_LOCAL0)
        handler = SysLogHandler(address=(syslog_handler_cnf.syslog_address, syslog_handler_cnf.syslog_port),
                                facility=facility)

        color_settings = general_cnf.color_settings
        enable_color = color_settings.enable_color
        log_format = CustomLogger._create_format(general_cnf.verbose, general_cnf.format, enable_color)

        if enable_color:
            formatter = ColoredFormatter(
                log_format,
                datefmt=color_settings.datefmt,
                reset=color_settings.reset,
                log_colors=color_settings.log_colors,
                secondary_log_colors=color_settings.secondary_log_colors,
                style=color_settings.style
            )
        else:
            formatter = Formatter(log_format)

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    @staticmethod
    def _setup_verbose_format(format_str):
        elements_to_add = [
            '%(funcName)s',
            '%(filename)s',
            '%(lineno)d'
        ]
        target_element = '%(module)s'

        if f'[{target_element}]' not in format_str and target_element not in format_str:
            return format_str

        def replace_element(target, element, format_str):
            if f'[{target}]' in format_str:
                return format_str.replace(f'[{target}]', f'[{target}][{element}]')
            else:
                return format_str.replace(target, f'{target}[{element}]')

        for element in elements_to_add:
            if element not in format_str:
                format_str = replace_element(target_element, element, format_str)
            target_element = element

        if '%(filename)s' in format_str and '%(lineno)d' in format_str:
            format_str = format_str.replace('[%(filename)s][%(lineno)d]', '[%(filename)s:%(lineno)d]')

        return format_str

    @staticmethod
    def _create_format(verbose, custom_format: str, enable_color=False):
        base_format = custom_format or "[%(asctime)s] [%(levelname)s][%(module)s]: %(message)s"
        if verbose:
            base_format = CustomLogger._setup_verbose_format(base_format)
        if enable_color:
            base_format = "%(log_color)s" + base_format
        return base_format

    @classmethod
    def reconfigure_logger(cls, logger: Logger, config):
        cls.configure_logger(logger, config)
