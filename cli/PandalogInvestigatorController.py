from cement.core.controller import CementBaseController, expose


class PandalogInvestigatorController(CementBaseController):
    class Meta:
        label = 'base'
        description = 'This application analyzes logs resulting from Panda sandbox run of malicious programs.'
        arguments = [
            (['-n', '--num'], dict(help='Specify the number of logs to operate on', action='store')),
            (['-a', '--all'], dict(help='Operate on all the logs in the folder', action='store_true'))
            ]

    @expose(hide=True)
    def default(self):
        print('Welcome to Pandalog Investigator')
        self.app.args.print_help()
        return

    @expose(help='Unpacking command: process compressed pandalogs and output the results on file. '
                 'Please specify the number of log files upon which you want to operate, or all.')
    def upck(self):
        print('Unpacking pandalogs')

        if not (self.app.pargs.num or self.app.pargs.all):
            self.app.args.print_help()
            return

        if self.app.pargs.num:
            print 'Received num option with value %s' % self.app.pargs.num
        if self.app.pargs.all:
            print 'Received all option'

        data = self.app.config.get('pandaloginvestigator', 'foo')
        print 'good' if data == u'bar' else 'bad'

    @expose(help='this is some help text about the cmd2')
    def cmd2(self):
        print('Inside BaseController.cmd2()')
