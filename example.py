from logflex.logflex import CustomLogger

def main():
    logger = CustomLogger(__name__, log_level='DEBUG', trace=False, verbose=True)
    logger.debug('This is a debug message.')
    logger.info('This is a Info message')
    logger.error('This is a Error message')

if __name__ == '__main__':
    main()
