from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.workers import worker_detect_regkey
from multiprocessing import Pool
import os
import logging
import time


logger = logging.getLogger(__name__)
empty_list = string_utils.no_instructions


# Checks the log files for malwares trying to access well known registry
# keys used to determine if the code is being executed with Qemu emulator.
def detect_reg_key(dir_pandalogs_path, dir_unpacked_path, dir_results_path, core_num):
    t1 = time.time()
    suspect_dict = {}
    filenames = sorted(utils.strip_filename_ext(os.listdir(dir_pandalogs_path)))
    file_names_sublists = utils.divide_workload(filenames, core_num)
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, [dir_unpacked_path, ])
    pool = Pool(processes=core_num)
    results = pool.map(worker_detect_regkey.work, formatted_input)
    pool.close()
    utils.update_results(results, [suspect_dict, ])
    file_utils.output_suspects(dir_results_path, suspect_dict)
    t2 = time.time()
    logger.info('Total detection time: ' + str(t2 - t1))

