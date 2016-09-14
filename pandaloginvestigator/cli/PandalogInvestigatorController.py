from cement.ext.ext_argparse import ArgparseController, expose
from .cmds.unpack import unpack_command
from .cmds.translate import translate_command
import logging


logger = logging.getLogger(__name__)


class PandalogInvestigatorController(ArgparseController):
    class Meta:
        label = 'base'
        description = 'This application analyzes logs resulting from Panda sandbox run of malicious programs.'

    @expose(hide=True)
    def default(self):
        self.app.args.print_help()

    @expose(help='Unpacking command: process compressed pandalogs and output the results on file. '
                 'Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
            ])
    def unpack(self):
        if self.app.pargs.num:
            logger.info('Unpacking logs. Received num option with value ' + str(self.app.pargs.num))
            unpack_command(self.app, int(self.app.pargs.num))
        else:
            logger.info('Unpacking all logs')
            unpack_command(self.app)

    @expose(help='Translation command: explicit system call names from unpacked pandalogs and output the results '
                 'on file. Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
            ])
    def translate(self):
        if self.app.pargs.num:
            logger.info('Translating logs. Received num option with value ' + str(self.app.pargs.num))
            translate_command(self.app, int(self.app.pargs.num))
        else:
            logger.info('Translating all logs')
            translate_command(self.app)

