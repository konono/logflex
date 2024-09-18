#!/usr/bin/env python
# -*- coding: utf-8 -*-

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import threading
import time
from logflex.logflex import CustomLogger

class ConfigFileChangeHandler(FileSystemEventHandler):
    def __init__(self, config_loader, logger):
        self.config_loader = config_loader
        self.logger = logger
        self.last_modified = 0
        self.debounce_interval = 1

    def on_modified(self, event):
        if event.src_path == str(self.config_loader.config_path):
            current_time = time.time()
            if current_time - self.last_modified > self.debounce_interval:
                self.last_modified = current_time
                self.logger.info(f"Config file was reloaded: {event.src_path}")
                success = self.config_loader.reload_config()
                if success:
                    CustomLogger.reconfigure_logger(self.logger, self.config_loader.config)
                else:
                    self.logger.warning("The logger was not reconfigured because the config file reload failed.")
def start_config_watcher(config_loader, logger):
    event_handler = ConfigFileChangeHandler(config_loader, logger)
    observer = Observer()
    observer.schedule(event_handler, path=str(config_loader.config_path.parent), recursive=False)
    observer_thread = threading.Thread(target=observer.start)
    observer_thread.daemon = True
    observer_thread.start()
