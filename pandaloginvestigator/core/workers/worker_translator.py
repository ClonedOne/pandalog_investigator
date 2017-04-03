from pandaloginvestigator.core.utils import string_utils
from os import path
import logging
import codecs

"""
Worker process in charge of translating system calls from their numerical code to their mnemonic strings.
"""

tag_system_call = string_utils.tag_system_call
logger = logging.getLogger(__name__)


def work(data_pack):
    """
    For each file in the filenames list, uses the system call dictionary passed
    to translate the system calls from number to explicit names, and save it to
    a separate folder.

    :param data_pack:
    :return:
    """
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path = data_pack[2]
    dir_translated_path = data_pack[3]
    syscall_dict = data_pack[4]
    j = 0.0
    total_files = len(filenames)
    logger.info('WorkerId = ' + str(worker_id) + ' translating ' + str(total_files) + ' log files')
    for filename in filenames:
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
        with open(path.join(dir_translated_path, filename), 'w', encoding='utf-8', errors='replace') as translated_file:
            with open(path.join(dir_unpacked_path, filename), 'r', encoding='utf-8', errors='replace') as log_file:
                for line in log_file:
                    if tag_system_call in line:
                        system_call_num = int(line.split('=')[3].split(')')[0])
                        system_call = syscall_dict.get(system_call_num, system_call_num)
                        new_line = line.split(':')[0] + ': ' + str(system_call)
                        translated_file.write(new_line + '\n')
                    else:
                        translated_file.write(line)
