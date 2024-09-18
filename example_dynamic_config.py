#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from logflex.logflex import CustomLogger

def main():
    logger = CustomLogger(__name__)

    try:
        while True:
            logger.debug('This is a debug message.')
            logger.info('This is an info message.')
            logger.error('This is an error message.')
            time.sleep(5)
    except KeyboardInterrupt:
        print("Terminated.")

if __name__ == '__main__':
    main()
