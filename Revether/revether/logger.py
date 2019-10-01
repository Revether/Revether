import logging


def initiate_logger(log_path, logger_name, log_level):
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    # Log to the IDA console using a streamhandler
    logger_stream_handler = logging.StreamHandler()
    log_stream_format = '[Revether][%(asctime)s][%(levelname)s] - %(message)s'
    fmt = logging.Formatter(log_stream_format, datefmt='%H:%M:%S')
    logger_stream_handler.setFormatter(fmt)
    logger.addHandler(logger_stream_handler)

    if log_path:
        # Log to the file in the log_path
        logger_file_handler = logging.FileHandler(log_path)
        log_file_format = '[%(asctime)s][%(levelname)s] - %(message)s'
        fmt = logging.Formatter(log_file_format, datefmt='%Y-%m-%d %H:%M:%S')
        logger_file_handler.setFormatter(fmt)
        logger.addHandler(logger_file_handler)

    return logger
