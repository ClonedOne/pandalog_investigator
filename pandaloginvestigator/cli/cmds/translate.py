from pandaloginvestigator.core import log_translator
from pandaloginvestigator.core.utils import syscalls_getter, pi_strings
import logging
import os


logger = logging.getLogger(__name__)


def translate_command(app, max_num=None):
    try:
        core_num = app.config.get('pandaloginvestigator', 'core_num')
    except:
        logger.error('core_num not set in configuration file')
        return
    if not os.path.exists(pi_strings.dir_unpacked_path):
        os.makedirs(pi_strings.dir_unpacked_path)
    if not os.path.exists(pi_strings.dir_translated_path):
        os.makedirs(pi_strings.dir_translated_path)
    logger.debug('Translate command with parameters: {}, {}, {}'.format(
        pi_strings.dir_unpacked_path, pi_strings.dir_translated_path, str(max_num)))
    syscall_dict = syscalls_getter.get_syscalls()
    log_translator.translate_logs(pi_strings.dir_unpacked_path, syscall_dict, pi_strings.dir_translated_path, core_num, max_num)
