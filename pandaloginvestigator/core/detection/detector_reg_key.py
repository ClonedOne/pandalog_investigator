from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.workers import worker_detect_regkey
from multiprocessing import Pool
import os
import logging


logger = logging.getLogger(__name__)
tags_reg_key = string_utils.tags_reg_key
empty_list = string_utils.no_instructions


# Checks the log files for malwares trying to access well known registry
# keys used to determine if the code is being executed with Qemu emulator.
def detect_reg_key(dir_unpacked_path, dir_results_path, core_num):
    term_sleep_dict = {}
    instruction_dict = {}
    filenames = sorted(os.listdir(dir_unpacked_path))
    file_names_sublists = utils.divide_workload(filenames, core_num)
    if len(file_names_sublists) != core_num:
        logger.error('ERROR: size of split workload different from number of cores')
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, dir_unpacked_path)
    pool = Pool(processes=core_num)
    results = pool.map(worker_detect_regkey.work, formatted_input)
    pool.close()


    avg_inst = 0.0
    number = 0.0
    for filename in filenames:
        scsi_count = filename_scsi_dict.get(filename, 0)
        bios_count = filename_bios_dict.get(filename, 0)
        condition = term_sleep_dict.get(filename, 'None')
        instructions = instruction_dict.get(filename, 0)
        if scsi_count or bios_count:
            avg_inst += instructions
            number += 1
            print(filename, scsi_count, bios_count, condition, instructions)
    avg_inst = avg_inst / number
    print('Average number of instructions: ', avg_inst)

