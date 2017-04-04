import logging
import os

from pandaloginvestigator.core.analysis import log_analyzer
from pandaloginvestigator.core.utils import string_utils

logger = logging.getLogger(__name__)


def analyze_command(app, max_num=None, small_disk=False):
    try:
        dir_pandalogs_path = app.config.get('pandaloginvestigator', 'dir_pandalogs_path')
    except:
        logger.error('dir_pandalogs_path not set in configuration file')
        return
    try:
        dir_database_path = app.config.get('pandaloginvestigator', 'dir_database_path')
    except:
        logger.error('dir_database_path not set in configuration file')
        return
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
        dir_panda_path = app.config.get('pandaloginvestigator', 'dir_panda_path')
    except:
        logger.error('dir_panda_path not set in configuration file')
        return

    dir_unpacked_path = created_dirs_path + '/' + string_utils.dir_unpacked_path
    if not os.path.exists(dir_unpacked_path):
        os.makedirs(dir_unpacked_path)

    dir_analyzed_path = created_dirs_path + '/' + string_utils.dir_analyzed_path
    if not os.path.exists(dir_analyzed_path):
        os.makedirs(dir_analyzed_path)

    dir_results_path = created_dirs_path + '/' + string_utils.dir_results_path
    if not os.path.exists(dir_results_path):
        os.makedirs(dir_results_path)

    logger.debug(
        'Analysis command with parameters: {}, {}, {}, {}, {}, {}, {}, {}, {}'.format(
            dir_panda_path,
            dir_pandalogs_path,
            dir_unpacked_path,
            dir_analyzed_path,
            dir_results_path,
            dir_database_path,
            str(core_num),
            str(max_num),
            str(small_disk)
        )
    )

    log_analyzer.analyze_logs(
        dir_panda_path,
        dir_pandalogs_path,
        dir_unpacked_path,
        dir_analyzed_path,
        dir_results_path,
        dir_database_path,
        core_num,
        max_num,
        small_disk
    )
