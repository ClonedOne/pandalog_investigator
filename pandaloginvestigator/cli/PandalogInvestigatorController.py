from cement.ext.ext_argparse import ArgparseController, expose
from pandaloginvestigator.cli.cmds.unpack import unpack_command
from pandaloginvestigator.cli.cmds.translate import translate_command
from pandaloginvestigator.cli.cmds.analyze import analyze_command
from pandaloginvestigator.cli.cmds.syscalls import syscall_command
from pandaloginvestigator.cli.cmds.detect import detect_command
from pandaloginvestigator.cli.cmds.graph import graph_command
import logging


logger = logging.getLogger(__name__)
help_n = 'Specify the number of logs to operate on'
help_u = 'Unpack log files before operation'
help_f = 'Unpack the log files listed in the specified file'
help_r = 'Detect the use of specific registry key to discover Qemu emulation'


class PandalogInvestigatorController(ArgparseController):
    class Meta:
        label = 'base'
        description = '''This application analyzes logs resulting from Panda
        sandbox run of malicious programs.'''
        arguments = [
            (['-n', '--num'], dict(help=help_n, action='store')),
            (['-u', '--unpack'], dict(help=help_u, action='store_true')),
            (['-i', '--instr'], dict(help=help_i, action='store_true')),
            (['-s', '--syscall'], dict(help=help_s, action='store_true')),
            (['-f', '--file'], dict(help=help_f, action='store')),
            (['-r', '--regkey'], dict(help=help_f, action='store_true'))
        ]

    @expose(hide=True)
    def default(self):
        self.app.args.print_help()

    @expose(help='''Unpacking command: process compressed pandalogs and output
    the results on file. Please specify the number of log files upon which you
    want to operate, or provide a list of log files or leave blank for all.''',
            arguments=[
                (['-n', '--num'], dict(help=help_n, action='store')),
                (['-u', '--unpack'], dict(help=help_u, action='store_true')),
                (['-f', '--file'], dict(help=help_f, action='store'))
            ])
    def unpack(self):
        logger.info(
            'Unpacking logs. Received num option with value {} and file option with value {}'.format(
                self.app.pargs.num,
                self.app.pargs.file
            )
        )
        if self.app.pargs.file:
            unpack_command(self.app, file_list=self.app.pargs.file)
        elif self.app.pargs.num:
            unpack_command(self.app, max_num=int(self.app.pargs.num))
        else:
            unpack_command(self.app)

    @expose(help='''Translation command: explicit system call names
    from unpacked pandalogs and output the results on file. Please
    specify the number of log files upon which you want to operate, or
    leave blank for all.''',
            arguments=[
                (['-n', '--num'], dict(help=help_n, action='store')),
                (['-u', '--unpack'], dict(help=help_u, action='store_true'))
            ])
    def translate(self):
        logger.info(
            'Translating logs. Received num option with value {}'.format(
                    self.app.pargs.num
            )
        )
        if self.app.pargs.unpack:
            self.unpack()
        if self.app.pargs.num:
            translate_command(self.app, int(self.app.pargs.num))
        else:
            translate_command(self.app)

    @expose(help='''Analysis command: identify malwares and corrupted processes
    and counts the instruction executed. Then outputs the results on file,
    generating also a final report file. Please specify the number of log files
    upon which you want to operate, or leave blank for all.''',
            arguments=[
                (['-n', '--num'], dict(help=help_n, action='store')),
                (['-u', '--unpack'], dict(help=help_u, action='store_true'))
            ])
    def analyze(self):
        logger.info(
            'Analyzing logs. Received num option with value {}'.format(
                self.app.pargs.num
            )
        )
        if self.app.pargs.unpack:
            self.unpack()
        if self.app.pargs.num:
            analyze_command(self.app, int(self.app.pargs.num))
        else:
            analyze_command(self.app)

    @expose(help='''System calls counting command: count system calls executed
                 by malicious programs. Then outputs the results on file,
                 generating also a final report file. Please specify the number
                 of log files upon which you want to operate, or all.''',
            arguments=[
                (['-n', '--num'], dict(help=help_n, action='store')),
                (['-u', '--unpack'], dict(help=help_u, action='store_true'))
            ])
    def syscalls(self):
        logger.info(
            'Counting system calls. Received num option with value {}'.format(
                    self.app.pargs.num
            )
        )
        if self.app.pargs.unpack:
            self.unpack()
        if self.app.pargs.num:
            syscall_command(self.app, int(self.app.pargs.num))
        else:
            syscall_command(self.app)

    @expose(help='''Detect attempts of sandbox detection: Generates a final
    statistics file. Please specify the kind of detection method you wish to
    look for, or leave blank for all.''',
            arguments=[
                (['-r', '--regkey'], dict(help=help_f, action='store_true'))
            ])
    def detect(self):
        logger.info(
            'Detecting sandbox detection techniques. Received option regkey with value {}'.format(
                self.app.pargs.regkey
            )
        )
        detect_command(self.app)

    @expose(help='''Represent corrupted processes as graphs, and output graph files
    compatible with gephi and cytoscape visualization libraries. Can be executed
    only after the analysis command.''',
            arguments=[

            ])
    def graph(self):
        logger.info('Generating graph output')
        graph_command(self.app)
