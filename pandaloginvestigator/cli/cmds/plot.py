from pandaloginvestigator.core.plotting import res_plotter
from pandaloginvestigator.core.utils import string_utils
import logging
import os


logger = logging.getLogger(__name__)


def plot_command(app, target):
    try:
        created_dirs_path = app.config.get('pandaloginvestigator', 'created_dirs_path')
    except:
        logger.error('created_dirs_path not set in configuration file')
        return

    dir_results_path = created_dirs_path + '/' + string_utils.dir_results_path
    if not os.path.exists(dir_results_path):
        os.makedirs(dir_results_path)

    logger.debug(
        'Plot command with parameters: {}, {}'.format(
            dir_results_path,
            target
        )
    )

    res_plotter.plot_results(
        dir_results_path,
        target
    )
