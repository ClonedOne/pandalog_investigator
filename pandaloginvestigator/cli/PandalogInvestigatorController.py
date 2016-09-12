from cement.ext.ext_argparse import ArgparseController, expose
from cmds.unpack import unpack_command


class PandalogInvestigatorController(ArgparseController):
    class Meta:
        label = 'base'
        description = 'This application analyzes logs resulting from Panda sandbox run of malicious programs.'

    # def _pre_argument_parsing(self):
    #     # Mutually exclusive groups
    #     meg = self.parser.add_mutually_exclusive_group()
    #     meg.add_argument('--g3', help='my g3 option')
    #     meg.add_argument('--g4', help='my g4 option')

    @expose(hide=True)
    def default(self):
        print('Welcome to Pandalog Investigator')
        self.app.args.print_help()
        return

    @expose(help='Unpacking command: process compressed pandalogs and output the results on file. '
                 'Please specify the number of log files upon which you want to operate, or all.',
            arguments=[
                (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
            ])
    def upck(self):
        print('Unpacking pandalogs')
        if not (self.app.pargs.num or self.app.pargs.all):
            self.app.args.print_help()
            return

        if self.app.pargs.num:
            print 'Received num option with value %s' % self.app.pargs.num
            unpack_command(self.app, int(self.app.pargs.num))
        print 'Unpacking all logs'
        unpack_command(self.app)

    @expose(help='this is some help text about the cmd2')
    def cmd2(self):
        print('Inside BaseController.cmd2()')
