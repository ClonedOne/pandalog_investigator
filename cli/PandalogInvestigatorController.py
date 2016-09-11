from cement.core.controller import CementBaseController, expose


class PandalogInvestigatorController(CementBaseController):
    class Meta:
        label = 'base'
        description = "This application analyzes logs resulting from Panda sandbox run of malicious programs."
        arguments = [
            (['-f', '--foo'], dict(help='notorious foo option')),
            (['-b', '--bar'], dict(help='infamous bar option')),
            ]

    @expose(hide=True)
    def default(self):
        print("Inside MyAppBaseController.default()")

    @expose(help="this is some help text about the cmd1")
    def cmd1(self):
        print("Inside BaseController.cmd1()")

    @expose(help="this is some help text about the cmd2")
    def cmd2(self):
        print("Inside BaseController.cmd2()")
