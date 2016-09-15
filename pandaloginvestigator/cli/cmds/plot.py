from pandaloginvestigator.core.plotting import res_plotter
from pandaloginvestigator.core.utils import pi_strings
import logging
import os


logger = logging.getLogger(__name__)


def plot_command(app, target):
    if not os.path.exists(pi_strings.dir_results_path):
        os.makedirs(pi_strings.dir_results_path)
    logger.debug('Plot command with parameters: {}, {}'.format(
        pi_strings.dir_results_path, target))
    res_plotter.plot_results(pi_strings.dir_results_path, target)
