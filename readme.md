#Panda Log Investigator

Welcome to Panda Log Investigator!
This software was developed to analyze the content of panda log files, generated using Platform for Architecture-Neutral Dynamic Analysis [PANDA](https://github.com/moyix/panda).

####Installation

Due to a problem with `numpy` dependency and setup.py, the classical `python setup.py install` will not work correctly.
Please install with `pip install -e .` to avoid the problem.

####Usage

The application contains a help menu which can be requested with `pandaloginvestigator -h`

####Known issues

There is a small issue with the logging function. It (seemingly) randomly raises and exception like:

    Traceback (most recent call last):
      File "/usr/lib/python3.5/multiprocessing/util.py", line 254, in _run_finalizers
        finalizer()
      File "/usr/lib/python3.5/multiprocessing/util.py", line 186, in __call__
        res = self._callback(*self._args, **self._kwargs)
      File "/usr/lib/python3.5/multiprocessing/queues.py", line 198, in _finalize_join
        thread.join()
      File "/usr/lib/python3.5/threading.py", line 1054, in join
        self._wait_for_tstate_lock()
      File "/usr/lib/python3.5/threading.py", line 1070, in _wait_for_tstate_lock
        elif lock.acquire(block, timeout):
      File "/home/yogaub/.virtualenvs/seminarvenv/lib/python3.5/site-packages/cement/core/foundation.py", line 123, in cement_signal_handler
        raise exc.CaughtSignal(signum, frame)
    cement.core.exc.CaughtSignal: Caught signal 15
    Process ForkPoolWorker-8:

While it may be annoying, the exception is related only to the logging code and does not in any way affect the overall execution of the application.
It is also only displayed in the console output, the debug and error rolling log files are not affected by the problem.