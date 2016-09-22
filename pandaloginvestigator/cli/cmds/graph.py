from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.plotting import graph_output
import logging
import os


logger = logging.getLogger(__name__)


def graph_command(app):
    if not os.path.exists(string_utils.dir_results_path):
        logger.error('ERROR graph_command dir_results_path not found')
        return
    graph_output.generate_graph(string_utils.dir_results_path)

