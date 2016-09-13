from pandaloginvestigator.core import log_translator
from pandaloginvestigator.core.utils import syscalls_getter
import logging


logger = logging.getLogger(__name__)


def translate_command(app, max_num=None):
    dir_unpacked_path = app.config.get('pandaloginvestigator', 'dir_unpacked_path')
    dir_translated_path = app.config.get('pandaloginvestigator', 'dir_translated_path')
    logger.debug('Translate command with parameters: {}, {}, {}'.format(
        dir_unpacked_path, dir_translated_path, str(max_num)))
    syscall_dict = syscalls_getter.get_syscalls()
    log_translator.translate_logs(dir_unpacked_path, syscall_dict, dir_translated_path, max_num)
