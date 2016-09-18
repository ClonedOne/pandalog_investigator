from pandaloginvestigator.core.plotting import res_plotter
from pandaloginvestigator.core.utils import string_utils
import logging
import os


logger = logging.getLogger(__name__)


def plot_command(app, target):
    if not os.path.exists(string_utils.dir_results_path):
        os.makedirs(string_utils.dir_results_path)
    logger.debug('Plot command with parameters: {}, {}'.format(
        string_utils.dir_results_path, target))
    res_plotter.plot_results(string_utils.dir_results_path, target)
