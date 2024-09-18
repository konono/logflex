from logflex.logflex import CustomLogger

def main():
    logger = CustomLogger(__name__)
    logger.debug('This is a debug message.')
    logger.info('This is a Info message')
    logger.error('This is a Error message')


    logger = CustomLogger(__name__, log_level='DEBUG', trace=True, verbose=False,
                          color_enable=True, file_logdir='./logs', file_logfile='app.log')
    logger.debug('This is a debug message.')
    logger.info('This is a Info message')
    logger.error('This is a Error message')

if __name__ == '__main__':
    main()
