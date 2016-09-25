from pandaloginvestigator.core import log_translator
from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import string_utils
import logging
import os


logger = logging.getLogger(__name__)


def translate_command(app, max_num=None):
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
        'Translate command with parameters: {}, {}, {}, {}'.format(
            dir_unpacked_path,
            dir_translated_path,
            core_num,
            str(max_num)
        )
    )
    syscall_dict = domain_utils.get_syscalls()
    log_translator.translate_logs(
        dir_unpacked_path,
        syscall_dict,
        dir_translated_path,
        core_num,
        max_num
    )
