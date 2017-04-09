from pandaloginvestigator.core.detection import suspect_builder
from pandaloginvestigator.core.utils import string_utils
import logging
import os


logger = logging.getLogger(__name__)


def detect_command(app):
    try:
        core_num = app.config.get('pandaloginvestigator', 'core_num')
    except:
        logger.error('core_num not set in configuration file')
        return
    try:
        created_dirs_path = app.config.get('pandaloginvestigator', 'created_dirs_path')
    except:
        logger.error('created_dirs_path not set in configuration file')
        return
    try:
        dir_redpills_path = app.config.get('pandaloginvestigator', 'dir_redpills_path')
    except:
        logger.error('dir_redpills_path not set in configuration file')
        return

    dir_results_path = created_dirs_path + '/' + string_utils.dir_results_path
    if not os.path.exists(dir_results_path):
        os.makedirs(dir_results_path)

    dir_analyzed_path = created_dirs_path + '/' + string_utils.dir_analyzed_path
    if not os.path.exists(dir_analyzed_path):
        os.makedirs(dir_analyzed_path)

    dir_clues_path = created_dirs_path + '/' + string_utils.dir_clues_path
    if not os.path.exists(dir_clues_path):
        os.makedirs(dir_clues_path)

    logger.debug(
        'Detect command with parameters: {}, {}, {}, {}, {}'.format(
            dir_results_path,
            dir_redpills_path,
            dir_analyzed_path,
            dir_clues_path,
            core_num,
        )
    )

    suspect_builder.build_suspects(dir_results_path, dir_redpills_path, dir_analyzed_path, dir_clues_path, core_num)
