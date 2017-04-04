from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.utils import panda_utils
from pandaloginvestigator.core.utils import string_utils
from os import path
import logging


logger = logging.getLogger(__name__)


def work(data_pack):
    """
    Pandalog suspicious registry keys detection worker. The data passed to each worker contains:
     * worker id - 0
     * list of file names to analyze - 1
     * path to the unpacked pandalog files - 2
     * flag indicating the need to delete unpacked files after analysis - 3
     * path to the pandalog unpacker utility - 4
     * path to the compressed pandalog files - 5

    :param data_pack: data needed by the worker 
    :return: dictionary of discovered clues
    """

    clues_dict = {}
    j = 0.0

    # Unpacking of the passed data
    worker_id = data_pack[0]
    file_names = data_pack[1]
    dir_unpacked_path = data_pack[2]
    small_disk = data_pack[3]
    dir_panda_path = data_pack[4]
    dir_pandalogs_path = data_pack[5]

    # Performance optimization
    tag_open_key = string_utils.tag_open_key
    tag_query_key = string_utils.tag_query_key
    tag_keys = string_utils.tag_keys
    tag_values = string_utils.tag_values

    total_files = len(file_names)
    logger.info('WorkerId {} detecting {} log files'.format(worker_id, total_files))

    for file_name in file_names:
        if small_disk:
            panda_utils.unpack_log(dir_panda_path, file_name + '.txz.plog', dir_pandalogs_path, dir_unpacked_path)
        cur_clue = Clue(file_name)
        clues_dict[file_name] = cur_clue

        with open(path.join(dir_unpacked_path, file_name), encoding='utf-8', errors='replace') as log_file:

            for line in log_file:
                if tag_open_key in line:
                    for tag in tag_keys:
                        if tag in line:
                            current_instruction, subject_pid, subject_name = panda_utils.data_from_line_basic(line)
                            cur_clue.add_opened_key((subject_name, subject_pid), tag)
                elif tag_query_key in line:
                    for tag in tag_values:
                        if tag in line:
                            current_instruction, subject_pid, subject_name = panda_utils.data_from_line_basic(line)
                            cur_clue.add_queried_key_value((subject_name, subject_pid), tag)

        if small_disk:
            panda_utils.remove_log_file(file_name, dir_unpacked_path)
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))

    return clues_dict


