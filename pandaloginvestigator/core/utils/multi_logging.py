from logging.handlers import RotatingFileHandler
from logging import Handler as LogHandler
import multiprocessing
import logging.config
import threading
import traceback
import codecs
import json
import sys
import os

# Refer http://stackoverflow.com/questions/641420/how-should-i-log-while-using-multiprocessing-in-python/894284#894284


def loadcfg(path, default_level=logging.INFO):
    if os.path.exists(path):
        print("Found logging config file")
        with codecs.open(path, 'r', encoding='utf8') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


class MultiProcessingFileHandler(LogHandler):
    def __init__(self, filename, mode='a', max_bytes=0, backup_count=0, encoding=None):
        LogHandler.__init__(self)
        self._handler = RotatingFileHandler(filename, mode, max_bytes, backup_count, encoding)
        self.queue = multiprocessing.Queue(-1)
        t = threading.Thread(target=self.receive)
        t.daemon = True
        t.start()

    def setFormatter(self, fmt):
        LogHandler.setFormatter(self, fmt)
        self._handler.setFormatter(fmt)

    def receive(self):
        while True:
            try:
                record = self.queue.get()
                self._handler.emit(record)
            except (KeyboardInterrupt, SystemExit):
                raise
            except EOFError:
                break
            except:
                pass
                traceback.print_exc(file=sys.stderr)

    def send(self, s):
        self.queue.put_nowait(s)

    def _format_record(self, record):
        if record.args:
            record.msg = record.msg % record.args
            record.args = None
        if record.exc_info:
            dummy = self.format(record)
            record.exc_info = None
        return record

    def emit(self, record):
        try:
            s = self._format_record(record)
            self.send(s)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def close(self):
        self._handler.close()
        LogHandler.close(self)
