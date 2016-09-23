from pandaloginvestigator.core.domain.suspect import Suspect
from pandaloginvestigator.core.utils import panda_utils
from pandaloginvestigator.core.utils import string_utils
import logging


logger = logging.getLogger(__name__)

tag_open_key = string_utils.tag_open_key
tag_query_key = string_utils.tag_query_key
tag_keys = string_utils.tag_keys
tag_values = string_utils.tag_values


def work(data_pack):
    suspect_dict = {}
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path = data_pack[2]
    j = 0.0
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId {} detecting {} log files'.format(worker_id, total_files))
    for filename in filenames:
        cur_suspect = Suspect(filename)
        suspect_dict[filename] = cur_suspect
        with open(dir_unpacked_path + '/' + filename, encoding='utf-8', errors='replace') as log_file:
            for line in log_file:
                if tag_open_key in line:
                    for tag in tag_keys:
                        if tag in line:
                            current_instruction, subject_pid, subject_name = panda_utils.data_from_line_d(line)
                            cur_suspect.add_opened_key((subject_name, subject_pid), tag)
                elif tag_query_key in line:
                    for tag in tag_values:
                        if tag in line:
                            current_instruction, subject_pid, subject_name = panda_utils.data_from_line_d(line)
                            cur_suspect.add_queried_key_value((subject_name, subject_pid), tag)
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
    return (suspect_dict, )


