from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core import log_syscall_counter
import logging
import os


logger = logging.getLogger(__name__)


def syscall_command(app, max_num=None):
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
    if not os.path.exists(string_utils.dir_unpacked_path):
        os.makedirs(string_utils.dir_unpacked_path)
    if not os.path.exists(string_utils.dir_syscall_path):
        os.makedirs(string_utils.dir_syscall_path)
    if not os.path.exists(string_utils.dir_results_path):
        os.makedirs(string_utils.dir_results_path)
    logger.debug('Syscalls command with parameters: {}, {}, {}'.format(
        string_utils.dir_unpacked_path, string_utils.dir_syscall_path, str(max_num)))
    log_syscall_counter.count_syscalls(string_utils.dir_unpacked_path,
                                       dir_database_path,
                                       string_utils.dir_results_path,
                                       string_utils.dir_syscall_path,
                                       core_num,
                                       max_num)
