from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.utils import panda_utils
from pandaloginvestigator.core.utils import string_utils
import logging


logger = logging.getLogger(__name__)

tag_open_key = string_utils.tag_open_key
tag_query_key = string_utils.tag_query_key
tag_keys = string_utils.tag_keys
tag_values = string_utils.tag_values


def work(data_pack):
    clues_dict = {}
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path = data_pack[2]
    small_disk = data_pack[3]
    dir_panda_path = data_pack[4]
    dir_pandalogs_path = data_pack[5]
    j = 0.0
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId {} detecting {} log files'.format(worker_id, total_files))

    for filename in filenames:
        if small_disk:
            panda_utils.unpack_log(dir_panda_path, filename + '.txz.plog', dir_pandalogs_path, dir_unpacked_path)
        cur_clue = Clue(filename)
        clues_dict[filename] = cur_clue

        with open(dir_unpacked_path + '/' + filename, encoding='utf-8', errors='replace') as log_file:

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
            panda_utils.remove_log_file(filename, dir_unpacked_path)
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))

    return [clues_dict, ]


