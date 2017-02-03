from pandaloginvestigator.cli.PandalogInvestigatorController import PandalogInvestigatorController
from cement.core.foundation import CementApp
from .core.utils import multi_logging


class PandalogInvestigatorApp(CementApp):
    class Meta:
        label = 'pandaloginvestigator'
        extensions = ['json']
        config_handler = 'json'
        base_controller = PandalogInvestigatorController
        catch_signals = None


def main():
    with PandalogInvestigatorApp() as app:
        multi_logging.loadcfg('logging.json')
        app.setup()
        app.config.parse_file('config.json')
        app.run()


if __name__ == '__main__':
    main()
