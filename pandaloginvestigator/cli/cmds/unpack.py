from pandaloginvestigator.core import log_unpacker
from pandaloginvestigator.core.utils import pi_strings
import logging
import os


logger = logging.getLogger(__name__)


def unpack_command(app, max_num=None):
    try:
        dir_pandalogs_path = app.config.get('pandaloginvestigator', 'dir_pandalogs_path')
    except:
        logger.debug('dir_pandalogs_path not set in configuration file')
        return
    try:
        dir_panda_path = app.config.get('pandaloginvestigator', 'dir_panda_path')
    except:
        logger.debug('dir_panda_path not set in configuration file')
        return
    if not os.path.exists(pi_strings.dir_unpacked_path):
        os.makedirs(pi_strings.dir_unpacked_path)
    logger.debug('Unpack command with parameters: {}, {}, {}, {}'.format(
        dir_pandalogs_path, dir_panda_path, pi_strings.dir_unpacked_path, str(max_num)))
    log_unpacker.unpack_logs(dir_pandalogs_path, dir_panda_path, pi_strings.dir_unpacked_path, max_num)
