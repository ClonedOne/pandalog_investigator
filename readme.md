#Panda Log Investigator

Welcome to Panda Log Investigator!
This software was developed to analyze the content of panda log files, generated using Platform for Architecture-Neutral Dynamic Analysis [PANDA](https://github.com/moyix/panda).
The objective of the investigator is to gather information regarding the execution of malware samples from the panda log files, and to possibly identify which malware samples adopted sandbox detection and evasion techniques.

####Installation

Due to a problem with `numpy` dependency and setup.py, the classical `python setup.py install` will not work correctly.
Please install with `pip install -e .` to avoid the problem.

####Usage

The application contains a help menu which can be requested with `pandaloginvestigator -h`

    optional arguments:
      -h, --help            show this help message and exit
      --debug               toggle debug output
      --quiet               suppress all output
      -o {json}             output handler
      -n NUM, --num NUM     Specify the number of logs to operate on
      -u, --unpack          Unpack log files before operation
      -i, --instr           Plot the result of the instruction anYalysis
      -s, --syscall         Plot the result of the system call analysis
      -f FILE, --file FILE  Unpack the log files listed in the specified file
      -r, --regkey          Unpack the log files listed in the specified file
      --small-disk          Disk size is too small to contain unpacked logs.
                            Remove each log after analysis
    
    sub-commands:
      {analyze,default,detect,graph,syscalls,translate,unpack}
        analyze             Analysis command: identify malwares and corrupted
                            processes and counts the instruction executed. Then
                            outputs the results on file, generating also a final
                            report file. Please specify the number of log files
                            upon which you want to operate, or leave blank for
                            all.
        detect              Detect attempts of sandbox detection: Generates a
                            final statistics file. Please specify the kind of
                            detection method you wish to look for, or leave blank
                            for all. Requires previous analysis.
        graph               Represent corrupted processes as graphs, and output
                            graph files compatible with Gephi visualization
                            library. Requires previous analysis.
        syscalls            System calls counting command: count system calls
                            executed by malicious programs. Then outputs the
                            results on file, generating also a final report file.
                            Please specify the number of log files upon which you
                            want to operate, or all.
        translate           Translation command: explicit system call names from
                            unpacked pandalogs and output the results on file.
                            Please specify the number of log files upon which you
                            want to operate, or leave blank for all.
        unpack              Unpacking command: process compressed pandalogs and
                            output the results on file. Please specify the number
                            of log files upon which you want to operate, or
                            provide a list of log files or leave blank for all.


####Known issues

There is a small issue with the logging function. 
It (seemingly) randomly raises and exception like:

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