from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.graph import graph_output
import logging
import os


logger = logging.getLogger(__name__)


def graph_command(app):
    try:
        created_dirs_path = app.config.get('pandaloginvestigator', 'created_dirs_path')
    except:
        logger.error('created_dirs_path not set in configuration file')
        return

    dir_results_path = created_dirs_path + '/' + string_utils.dir_results_path
    if not os.path.exists(dir_results_path):
        os.makedirs(dir_results_path)

    logger.debug(
        'Graph command with parameters: {}'.format(
            dir_results_path
        )
    )

    graph_output.generate_graph(dir_results_path)

