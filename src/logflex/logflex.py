#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pathlib
import traceback

from typing import List
from logging import getLogger, StreamHandler, Formatter, Filter, ERROR
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
from colorlog import ColoredFormatter
from logflex.config.settings import ConfigLoader, ConfigBuilder
from logflex.models.config_model import FACILITY_MAP


def stacktrace_lines() -> List[str]:
    tb = traceback.format_stack()
    ret = []
    path = pathlib.Path.cwd()
    for line in tb:
        p = line.find("\n")
        if p >= 0:
            line = line[:p].strip() + ": " + line[p + 1:].strip()
        if line.startswith(f'File \"{path}') and '/logflex/logflex.py' not in line:
            ret.append(line)
    return ret

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
    def __new__(cls, module: str, config_path=None, **kwargs):
        if kwargs:
            config = ConfigBuilder.build_config(**kwargs)
        else:
            config_loader = ConfigLoader(config_path)
            config = config_loader.config

        logger = getLogger(module)

        if config.general.trace:
            logger.addFilter(StackTraceFilter())

        logger.setLevel(config.general.log_level)
        logger.propagate = False

        cls._add_stream_handler(logger, config)

        if config.file_handler.logdir:
            cls._add_file_handler(logger, config)

        if config.file_handler.dedicate_error_logfile:
            cls._add_error_handler(logger, config)

        if config.syslog_handler.use_syslog:
            cls._add_syslog_handler(logger, config)

        return logger

    @staticmethod
    def _add_stream_handler(logger, config):
        formatter = CustomLogger._setup_colored_logging(
            CustomLogger._create_format(config.general.verbose, config.general.color_settings.enable_color),
            config.general.color_settings
        )
        handler = StreamHandler()
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    @staticmethod
    def _setup_colored_logging(format_str, color_settings):
        if color_settings.enable_color:
            return ColoredFormatter(
                format_str,
                datefmt=color_settings.datefmt,
                reset=color_settings.reset,
                log_colors=color_settings.log_colors,
                secondary_log_colors=color_settings.secondary_log_colors,
                style=color_settings.style
            )
        else:
            return Formatter(format_str)

    @staticmethod
    def _add_file_handler(logger, config):
        file_handler_cnf = config.file_handler
        general_cnf = config.general
        log_file_path = os.path.join(file_handler_cnf.logdir,
                                     file_handler_cnf.logfile or f"{logger.name}.log")
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

        handler = TimedRotatingFileHandler(
            log_file_path, when=file_handler_cnf.when,
            interval=file_handler_cnf.interval,
            backupCount=file_handler_cnf.backup_count
        )
        if file_handler_cnf.dedicate_error_logfile:
            handler.addFilter(ErrorBelowFilter())
        formatter = Formatter(CustomLogger._create_format(general_cnf.verbose))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    @staticmethod
    def _add_error_handler(logger, config):
        file_handler_cnf = config.file_handler
        log_file_path = os.path.join(file_handler_cnf.logdir, file_handler_cnf.logfile or f"{logger.name}.log")
        error_file_path = os.path.splitext(log_file_path)[0] + "_error.log"
        handler = TimedRotatingFileHandler(
            error_file_path, when=file_handler_cnf.when,
            interval=file_handler_cnf.interval,
            backupCount=file_handler_cnf.backup_count
        )
        handler.setLevel('ERROR')
        formatter = Formatter(CustomLogger._create_format(False))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    @staticmethod
    def _add_syslog_handler(logger, config):
        syslog_handler_cnf = config.syslog_handler
        facility = FACILITY_MAP.get(syslog_handler_cnf.syslog_facility, SysLogHandler.LOG_LOCAL0)
        handler = SysLogHandler(address=(syslog_handler_cnf.syslog_address, syslog_handler_cnf.syslog_port),
                                facility=facility)
        formatter = Formatter(CustomLogger._create_format(False))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    @staticmethod
    def _create_format(verbose, enable_color=False):
        base_format = "[%(asctime)s] [%(levelname)s][%(module)s]"
        if enable_color:
            base_format = "%(log_color)s" + base_format
        if verbose:
            base_format += "[%(funcName)s][%(filename)s:%(lineno)d]"
        base_format += ": %(message)s"
        return base_format
