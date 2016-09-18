from pandaloginvestigator.core import log_translator
from pandaloginvestigator.core.utils import syscalls_getter, string_utils
import logging
import os


logger = logging.getLogger(__name__)


def translate_command(app, max_num=None):
    try:
        core_num = app.config.get('pandaloginvestigator', 'core_num')
    except:
        logger.error('core_num not set in configuration file')
        return
    if not os.path.exists(string_utils.dir_unpacked_path):
        os.makedirs(string_utils.dir_unpacked_path)
    if not os.path.exists(string_utils.dir_translated_path):
        os.makedirs(string_utils.dir_translated_path)
    logger.debug('Translate command with parameters: {}, {}, {}'.format(
        string_utils.dir_unpacked_path, string_utils.dir_translated_path, str(max_num)))
    syscall_dict = syscalls_getter.get_syscalls()
    log_translator.translate_logs(string_utils.dir_unpacked_path, syscall_dict, string_utils.dir_translated_path, core_num, max_num)
