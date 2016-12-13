from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.utils import string_utils
import logging


logger = logging.getLogger(__name__)
features = [
    string_utils.current_process,
    string_utils.current_pid,
    string_utils.parent_pid,
    string_utils.instruction_mnemonic,
    string_utils.instruction_operands,
    string_utils.instruction_size,
    string_utils.instruction_bytes
]


def work(data_pack):
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_clues_path = data_pack[2]
    corrupted_dict = data_pack[3]
    j = 0.0
    clues_dict = {}
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId {} reading {} clues files'.format(worker_id, total_files))

    for filename in filenames:
        with open(dir_clues_path + '/' + filename, encoding='utf-8', errors='replace') as clue_file:
            filename = filename[:-7]
            new_clue = Clue(filename)
            cur_features = [None] * 7

            for line in clue_file:

                if not line.strip() and cur_features[0] is not None:
                    cur_proc = (cur_features[0], cur_features[1])

                    if is_corrupted(filename, cur_proc, corrupted_dict):
                        if int(cur_features[5]) >= 15:
                            tag_inst = 'oversize'
                        else:
                            tag_inst = cur_features[3]
                        new_clue.add_dangerous_instructions(cur_proc, tag_inst)
                        clues_dict[filename] = new_clue

                    cur_features = [None] * 7

                else:
                    split_line = line.split(':')
                    for i in range(len(features)):
                        if features[i] == split_line[0]:
                            cur_features[i] = split_line[1].strip()

        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))

    return (clues_dict, )


def is_corrupted(filename, cur_proc, corrupted_dict):
    """
    Checks if a clue is relative to a corrupted process

    :param filename:
    :param cur_proc:
    :param corrupted_dict:
    :return: True if cur_proc is in corrupted_dict, else False.
    """
    corrupted_procs = corrupted_dict.get(filename, [])
    for proc in corrupted_procs:
        if proc[0] == cur_proc:
            return True

    return False


