import logging
import os
import time
from multiprocessing import Pool

from pandaloginvestigator.core.detection import worker_regkey_detector
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils

logger = logging.getLogger(__name__)
empty_list = string_utils.no_instructions


def detect_reg_key(dir_pandalogs_path, dir_unpacked_path, dir_results_path, core_num):
    """
    Checks the log files for malwares trying to access well known registry
    keys used to determine if the code is being executed with Qemu emulator.
    :param dir_pandalogs_path:
    :param dir_unpacked_path:
    :param dir_results_path:
    :param core_num:
    :return:
    """
    t1 = time.time()
    suspect_dict = {}
    filenames = sorted(os.listdir(dir_unpacked_path))
    file_names_sublists = utils.divide_workload(filenames, core_num)
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, [dir_unpacked_path, ])
    pool = Pool(processes=core_num)
    results = pool.map(worker_regkey_detector.work, formatted_input)
    pool.close()
    utils.update_results(results, [suspect_dict, ])
    file_utils.output_regkey_clues(dir_results_path, suspect_dict)
    t2 = time.time()
    logger.info('Total detection time: ' + str(t2 - t1))
