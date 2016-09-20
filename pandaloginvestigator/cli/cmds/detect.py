from pandaloginvestigator.core.detection import detector_reg_key
from pandaloginvestigator.core.utils import string_utils
import logging
import os


logger = logging.getLogger(__name__)


def detect_command(app):
    if not os.path.exists(string_utils.dir_unpacked_path):
        os.makedirs(string_utils.dir_unpacked_path)
    if not os.path.exists(string_utils.dir_results_path):
        os.makedirs(string_utils.dir_results_path)
    try:
        core_num = app.config.get('pandaloginvestigator', 'core_num')
    except:
        logger.error('core_num not set in configuration file')
        return
    if app.pargs.regkey:
        detector_reg_key.detect_reg_key(string_utils.dir_unpacked_path, string_utils.dir_results_path, core_num)
    else:
        detector_reg_key.detect_reg_key(string_utils.dir_unpacked_path, string_utils.dir_results_path, core_num)