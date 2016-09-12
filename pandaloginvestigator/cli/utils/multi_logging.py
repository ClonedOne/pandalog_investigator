import os
import json
import logging.config
import multiprocessing
import sys
import threading
import traceback
from logging import Handler as LogHandler
from logging.handlers import RotatingFileHandler


def loadcfg(default_path='logging.json',
            default_level=logging.INFO,
            env_key='LOG_CFG'):
    env = os.getenv(env_key, None)
    path = default_path if not env else env
    if os.path.exists(path):
        with open(path, 'r', encoding='utf8') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


class MultiProcessingFileHandler(LogHandler):

    def __init__(self, filename,
                 mode='a', maxBytes=0, backupCount=0, encoding=None):
        LogHandler.__init__(self)
        self._handler = RotatingFileHandler(filename, mode, maxBytes,
                                            backupCount, encoding)
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
                # print('received on pid {}'.format(os.getpid()))
            except (KeyboardInterrupt, SystemExit):
                raise
            except EOFError:
                break
            except:
                traceback.print_exc(file=sys.stderr)

    def send(self, s):
        self.queue.put_nowait(s)

    def _format_record(self, record):
        # ensure that exc_info and args have been stringified.
        # Removes any chance of unpickleable things inside and
        # possibly reduces message size sent over the pipe
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
