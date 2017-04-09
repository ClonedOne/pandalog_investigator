# PANDALog Investigator

Welcome to Panda Log Investigator!
This software was developed to analyze the content of panda log files, generated using Platform for Architecture-Neutral Dynamic Analysis [PANDA](https://github.com/moyix/panda).
The objective of the investigator is to gather information regarding the execution of malware samples from the panda log files, and to possibly identify which malware samples adopted sandbox detection and evasion techniques.

#### Installation

Due to a problem with `numpy` dependency and setup.py, the classical `python setup.py install` will not work correctly.
Please install with `pip install -e .` to avoid the problem.

#### Usage

The application contains a help menu which can be requested with `pandaloginvestigator -h`

    optional arguments:
      -h, --help            show this help message and exit
      --debug               toggle debug output
      --quiet               suppress all output
      -o {json}             output handler
      -n NUM, --num NUM     Specify the number of logs to operate on
      -u, --unpack          Unpack log files before operation
      -f FILE, --file FILE  Unpack the log files listed in the specified file
      -s, --small-disk      Disk size is too small to contain unpacked logs.
                            Remove each log after analysis

    sub-commands:
      {analyze,default,detect,graph,translate,unpack}
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
                            graph files compatible with visualization libraries.
                            Requires previous analysis.
        translate           Translation command: explicit system call names from
                            unpacked pandalogs and output the results on file.
                            Please specify the number of log files upon which you
                            want to operate, or leave blank for all.
        unpack              Unpacking command: process compressed pandalogs and
                            output the results on file. Please specify the number
                            of log files upon which you want to operate, or
                            provide a list of log files or leave blank for all.

The Investigator can be used alone. However if provided with the results of the [Investigator plugin](https://github.com/ClonedOne/panda_plugins_c1) for PANDA, the Investigator will be able to identify more sandbox detection techniques. 
