import logging
import time
from multiprocessing import Pool

from pandaloginvestigator.core.detection import worker_regkey_detector
from pandaloginvestigator.core.io import file_output
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils

logger = logging.getLogger(__name__)
empty_list = string_utils.no_instructions


def detect_reg_key(dir_panda_path, dir_pandalogs_path, dir_unpacked_path, dir_results_path, core_num, small_disk,
                   max_num):
    """
    Checks the log files for malwares trying to access well known registry
    keys used to determine if the code is being executed with Qemu emulator.

    :param dir_panda_path:
    :param dir_pandalogs_path:
    :param dir_unpacked_path:
    :param dir_results_path:
    :param core_num:
    :param small_disk:
    :param max_num:
    :return:
    """
    t1 = time.time()
    logger.info('Starting detection operation with max_num = ' + str(max_num))
    suspect_dict = {}
    filenames, max_num = utils.input_with_modifiers(dir_unpacked_path, dir_pandalogs_path, small_disk=small_disk,
                                                    max_num=max_num)
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    formatted_input = utils.format_worker_input(
        core_num,
        file_names_sublists,
        (
            dir_unpacked_path,
            small_disk,
            dir_panda_path,
            dir_pandalogs_path
        )

    )
    pool = Pool(processes=core_num)
    results = pool.map(worker_regkey_detector.work, formatted_input)
    pool.close()
    pool.join()
    utils.update_results(results, [suspect_dict, ])
    file_output.output_clues(dir_results_path, suspect_dict, 'clues_regkey.txt')
    t2 = time.time()
    logger.info('Total detection time: ' + str(t2 - t1))
