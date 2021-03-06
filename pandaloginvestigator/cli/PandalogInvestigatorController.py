from pandaloginvestigator.cli.cmds.translate import translate_command
from pandaloginvestigator.cli.cmds.analyze import analyze_command
from pandaloginvestigator.cli.cmds.unpack import unpack_command
from pandaloginvestigator.cli.cmds.detect import detect_command
from cement.ext.ext_argparse import ArgparseController, expose
from pandaloginvestigator.cli.cmds.graph import graph_command
import logging


logger = logging.getLogger(__name__)
help_n = 'Specify the number of logs to operate on'
help_u = 'Unpack log files before operation'
help_f = 'Unpack the log files listed in the specified file'
help_r = 'Detect the use of specific registry key to discover Qemu emulation'
help_s = 'Disk size is too small to contain unpacked logs. Remove each log after analysis'


class PandalogInvestigatorController(ArgparseController):
    class Meta:
        label = 'base'
        description = '''This application analyzes logs resulting from Panda
        sandbox run of malicious programs.'''
        arguments = [
            (['-n', '--num'], dict(help=help_n, action='store')),
            (['-u', '--unpack'], dict(help=help_u, action='store_true')),
            (['-f', '--file'], dict(help=help_f, action='store')),
            (['-s', '--small-disk'], dict(help=help_s, action='store_true'))

        ]

    @expose(hide=True)
    def default(self):
        self.app.args.print_help()

    @expose(help='''Unpacking command: process compressed pandalogs and output
    the results on file. Please specify the number of log files upon which you
    want to operate, or provide a list of log files or leave blank for all.''',
            arguments=[
                (['-n', '--num'], dict(help=help_n, action='store')),
                (['-f', '--file'], dict(help=help_f, action='store'))
            ])
    def unpack(self):
        logger.info(
            'Unpacking logs. Received num option with value {} and file list option with value {}'.format(
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
                (['-u', '--unpack'], dict(help=help_u, action='store_true')),
                (['-s', '--small-disk'], dict(help=help_s, action='store_true'))
            ])
    def translate(self):
        logger.info(
            'Translating logs. Received num option with value {} {} {}'.format(
                self.app.pargs.unpack,
                self.app.pargs.num,
                self.app.pargs.small_disk
            )
        )
        unpack = False
        max_num = None
        small_disk = False
        if self.app.pargs.unpack:
            unpack = True
        if self.app.pargs.num:
            max_num = self.app.pargs.num
        if self.app.pargs.small_disk:
            small_disk = True
            if unpack:
                unpack = False
        if unpack:
            self.unpack()

        translate_command(self.app, max_num, small_disk)

    @expose(help='''Analysis command: identify malwares and corrupted processes
    and counts the instruction executed. Then outputs the results on file,
    generating also a final report file. Please specify the number of log files
    upon which you want to operate, or leave blank for all.''',
            arguments=[
                (['-n', '--num'], dict(help=help_n, action='store')),
                (['-u', '--unpack'], dict(help=help_u, action='store_true')),
                (['-s', '--small-disk'], dict(help=help_s, action='store_true'))
            ])
    def analyze(self):
        logger.info(
            'Analyzing logs. Received options value {} {} {}'.format(
                self.app.pargs.unpack,
                self.app.pargs.num,
                self.app.pargs.small_disk
            )
        )
        unpack = False
        max_num = None
        small_disk = False
        if self.app.pargs.unpack:
            unpack = True
        if self.app.pargs.num:
            max_num = self.app.pargs.num
        if self.app.pargs.small_disk:
            small_disk = True
            if unpack:
                unpack = False
        if unpack:
            self.unpack()

        analyze_command(self.app, max_num, small_disk)

    @expose(help='''Detect attempts of sandbox detection: Generates a final
    statistics file. Please specify the kind of detection method you wish to
    look for, or leave blank for all. Requires previous analysis.''',
            arguments=[])
    def detect(self):
        logger.info('Detecting sandbox detection/evasion.')
        detect_command(self.app)

    @expose(help='''Represent corrupted processes as graphs, and output graph files
    compatible with visualization libraries. Requires previous analysis.''',
            arguments=[])
    def graph(self):
        logger.info('Generating graph output')
        graph_command(self.app)
