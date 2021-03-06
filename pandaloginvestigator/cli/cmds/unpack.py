import logging
import os

from pandaloginvestigator.core.analysis import log_unpacker
from pandaloginvestigator.core.utils import string_utils

logger = logging.getLogger(__name__)


def unpack_command(app, file_list=None, max_num=None):
    try:
        dir_pandalogs_path = app.config.get('pandaloginvestigator', 'dir_pandalogs_path')
    except:
        logger.error('dir_pandalogs_path not set in configuration file')
        return
    try:
        dir_panda_path = app.config.get('pandaloginvestigator', 'dir_panda_path')
    except:
        logger.error('dir_panda_path not set in configuration file')
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

    dir_unpacked_path = os.path.join(created_dirs_path, string_utils.dir_unpacked_path)
    if not os.path.exists(dir_unpacked_path):
        os.makedirs(dir_unpacked_path)

    if file_list and not os.path.exists(file_list):
        logger.error('Specified file list does not exist')
        return

    logger.debug(
        'Unpack command with parameters: {}, {}, {}, {}, {}, {}'.format(
            dir_pandalogs_path,
            dir_panda_path,
            dir_unpacked_path,
            core_num,
            file_list,
            str(max_num)
        )
    )
    log_unpacker.unpack_logs(
        dir_pandalogs_path,
        dir_panda_path,
        dir_unpacked_path,
        core_num,
        file_list,
        max_num
    )
