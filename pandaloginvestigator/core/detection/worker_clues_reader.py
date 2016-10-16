from pandaloginvestigator.core.utils import string_utils
import logging


logger = logging.getLogger(__name__)


def work(data_pack):
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_clues_path = data_pack[2]
    corrupted_dict = data_pack[3]
    j = 0.0
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId {} reading {} clues files'.format(worker_id, total_files))
    for filename in filenames:
        with open(dir_clues_path + '/' + filename, encoding='utf-8', errors='replace') as clue_file:
            proc_name, cur_pid, par_pid, mnem, ops, ins_size, ins_bytes = None
            for line in clue_file:
                if string_utils.current_process in line:
                    proc_name = line.split(':')[1].strip()
                if string_utils.current_pid in line:
                    cur_pid = line.split(':')[1].strip()
                if string_utils.parent_pid in line:
                    par_pid = line.split(':')[1].strip()
                if string_utils.instruction_mnemonic in line:
                    mnem = line.split(':')[1].strip()
                if string_utils.instruction_operands in line:
                    ops = line.split(':')[1].strip()
                if string_utils.instruction_size in line:
                    ins_size = int(line.split(':')[1].strip())
                if string_utils.instruction_bytes in line:
                    ins_bytes = line.split(':')[1].strip()
                    print(proc_name, cur_pid, par_pid, mnem, ops, ins_size, ins_bytes)
