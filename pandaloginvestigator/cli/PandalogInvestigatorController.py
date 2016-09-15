from cement.ext.ext_argparse import ArgparseController, expose
from pandaloginvestigator.cli.cmds.unpack import unpack_command
from pandaloginvestigator.cli.cmds.translate import translate_command
from pandaloginvestigator.cli.cmds.analyze import analyze_command
from pandaloginvestigator.cli.cmds.syscalls import syscall_command
import logging


logger = logging.getLogger(__name__)


class PandalogInvestigatorController(ArgparseController):
    class Meta:
        label = 'base'
        description = 'This application analyzes logs resulting from Panda sandbox run of malicious programs.'
        arguments = [
            (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
            (['-u', '--unpack'], dict(help='Unpack log files before operation', action='store_true'))
        ]

    @expose(hide=True)
    def default(self):
        self.app.args.print_help()

    @expose(help='Unpacking command: process compressed pandalogs and output the results on file. '
                 'Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
                (['-u', '--unpack'], dict(help='Unpack log files before operation', action='store_true'))
            ])
    def unpack(self):
        logger.info('Unpacking logs. Received num option with value ' + str(self.app.pargs.num))
        if self.app.pargs.num:
            unpack_command(self.app, int(self.app.pargs.num))
        else:
            unpack_command(self.app)

    @expose(help='Translation command: explicit system call names from unpacked pandalogs and output the results '
                 'on file. Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
                (['-u', '--unpack'], dict(help='Unpack log files before operation', action='store_true'))
            ])
    def translate(self):
        logger.info('Translating logs. Received num option with value ' + str(self.app.pargs.num))
        if self.app.pargs.unpack:
            self.unpack()
        if self.app.pargs.num:
            translate_command(self.app, int(self.app.pargs.num))
        else:
            translate_command(self.app)

    @expose(help='Analysis command: identify malwares and corrupted processes and counts the instruction executed. '
                 'Then outputs the results on file, generating also a final report file. '
                 'Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
                (['-u', '--unpack'], dict(help='Unpack log files before operation', action='store_true'))
            ])
    def analyze(self):
        logger.info('Analyzing logs. Received num option with value ' + str(self.app.pargs.num))
        if self.app.pargs.unpack:
            self.unpack()
        if self.app.pargs.num:
            analyze_command(self.app, int(self.app.pargs.num))
        else:
            analyze_command(self.app)

    @expose(help='System calls counting command: count system calls executed by malicious programs. '
                 'Then outputs the results on file, generating also a final report file. '
                 'Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
                (['-u', '--unpack'], dict(help='Unpack log files before operation', action='store_true'))
            ])
    def syscalls(self):
        logger.info('Counting system calls. Received num option with value ' + str(self.app.pargs.num))
        if self.app.pargs.unpack:
            self.unpack()
        if self.app.pargs.num:
            syscall_command(self.app, int(self.app.pargs.num))
        else:
            syscall_command(self.app)

    @expose(help='Analysis result plotting command: generate result graphs and statistics. '
                 'Generates also a final statistics file. '
                 'Please specify the result you wish to visualize: instructions or system calls analysis.',
            arguments=[
                (['-i', '--instr'], dict(help='Plot the result of the instruction analysis', action='store_true')),
                (['-s', '--syscall'], dict(help='Plot the result of the system call analysis', action='store_true'))
            ])
    def plot(self):
        logger.info('Plotting analysis results. Received option: ' + ('syscalls' if self.app.pargs.syscall else 'instructions'))
        if self.app.pargs.num:
            syscall_command(self.app, int(self.app.pargs.num))
        elif self.app.pargs.syscall:
            syscall_command(self.app)
        else:
            logger.info('Must specify a parameter')
            self.app.args.print_help()
