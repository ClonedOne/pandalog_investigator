from pandaloginvestigator.core.detection import detector_regkey
from pandaloginvestigator.core.utils import string_utils
import logging
import os


logger = logging.getLogger(__name__)


def detect_command(app):
    try:
        dir_pandalogs_path = app.config.get('pandaloginvestigator', 'dir_pandalogs_path')
    except:
        logger.error('dir_pandalogs_path not set in configuration file')
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

    dir_unpacked_path = created_dirs_path + '/' + string_utils.dir_unpacked_path
    if not os.path.exists(dir_unpacked_path):
        os.makedirs(dir_unpacked_path)

    dir_results_path = created_dirs_path + '/' + string_utils.dir_results_path
    if not os.path.exists(dir_results_path):
        os.makedirs(dir_results_path)

    logger.debug(
        'Detect command with parameters: {}, {}, {}, {}, {}'.format(
            dir_pandalogs_path,
            dir_unpacked_path,
            dir_results_path,
            core_num,
            app.pargs.regkey
        )
    )

    if app.pargs.regkey:
        detector_regkey.detect_reg_key(dir_pandalogs_path, dir_unpacked_path, dir_results_path, core_num)
    else:
        # Possibly other detectors will be called here
        detector_regkey.detect_reg_key(dir_pandalogs_path, dir_unpacked_path, dir_results_path, core_num)