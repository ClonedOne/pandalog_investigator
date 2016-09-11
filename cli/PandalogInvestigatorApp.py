import PandalogInvestigatorController
from cement.core.foundation import CementApp


class PandalogInvestigatorApp(CementApp):
    class Meta:
        label = 'pandaloginvestigator'
        extensions = ['json']
        config_handler = 'json'
        base_controller = PandalogInvestigatorController.PandalogInvestigatorController
