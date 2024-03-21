import logging

log_handle = logging.getLogger("hijack_hunter")

def setup_logger(verbose: bool) -> None:
    if verbose:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG

    log_handle.setLevel(log_level)

    # Create a console handler with a higher log level
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(CustomFormatter())
    log_handle.addHandler(stream_handler)

    file_stream_handler = logging.FileHandler('result.log')
    file_stream_handler.setLevel(log_level)
    file_stream_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    log_handle.addHandler(file_stream_handler)

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    green = "\x1b[1;32m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_problem_str = "%(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + "%(levelname)s - %(message)s" + reset,
        logging.INFO: green +  "%(levelname)s" + reset + " - %(message)s",
        logging.WARNING: yellow + format_problem_str + reset,
        logging.ERROR: red + format_problem_str + reset,
        logging.CRITICAL: bold_red + format_problem_str + reset
    }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class LOG:
    @staticmethod
    def debug(msg):
        return log_handle.debug(msg)
    @staticmethod
    def info(msg):
        return log_handle.info(msg)
    @staticmethod
    def warning(msg):
        return log_handle.warning(msg)
    @staticmethod
    def error(msg):
        return log_handle.error(msg)
    @staticmethod
    def critical(msg):
        return log_handle.critical(msg)