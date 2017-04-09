import logging
import os

import pandaloginvestigator.core.io.file_input
from pandaloginvestigator.core.analysis import log_translator
from pandaloginvestigator.core.utils import string_utils

logger = logging.getLogger(__name__)


def translate_command(app, file_list=None, max_num=None):
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

    dir_translated_path = created_dirs_path + '/' + string_utils.dir_translated_path
    if not os.path.exists(dir_translated_path):
        os.makedirs(dir_translated_path)

    logger.debug(
        'Translate command with parameters: {}, {}, {}, {}, {}, {}'.format(
            dir_pandalogs_path,
            dir_unpacked_path,
            dir_translated_path,
            core_num,
            file_list,
            str(max_num),
        )
    )
    syscall_dict = pandaloginvestigator.core.io.file_input.get_syscalls()
    log_translator.translate_logs(
        dir_pandalogs_path,
        dir_unpacked_path,
        syscall_dict,
        dir_translated_path,
        core_num,
        file_list,
        max_num
    )
