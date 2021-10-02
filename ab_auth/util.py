import logging
import sys

FORMAT = '[%(asctime)s] [%(threadName)s/%(levelname)s] [%(filename)s:%(lineno)i] %(message)s'
DATE_FORMAT = '%H:%M:%S'

COLORS = {
    'WARN': '33',
    'DEBUG': '36',
    'SEVERE': '41;37',
    'ERROR': '31'
}

RESET_SEQ = '\033[0m'
COLOR_SEQ = '\033[%sm'

DEBUG = '--debug' in sys.argv


class ColoredFormatter(logging.Formatter):
    use_color: bool

    def __init__(self, use_color: bool = True):
        super().__init__(FORMAT, DATE_FORMAT)
        self.use_color = use_color

    def format(self, record: logging.LogRecord):
        levelname = record.levelname
        message = super().format(record)
        if self.use_color and levelname in COLORS:
            message = COLOR_SEQ % COLORS[levelname] + message + RESET_SEQ
        return message


def init_logger(log_file: str) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if DEBUG else logging.INFO)
    logging.addLevelName(logging.WARN, 'WARN')
    logging.addLevelName(logging.CRITICAL, 'SEVERE')
    handlers: list[logging.Handler] = [
        logging.StreamHandler(),
        logging.FileHandler(log_file, 'w', encoding='utf-8'),
    ]
    handlers[0].setFormatter(ColoredFormatter(True))
    handlers[1].setFormatter(ColoredFormatter(False))
    for handler in handlers:
        root.addHandler(handler)
