from multiprocessing import Pool
from pandaloginvestigator.core.workers import worker_translator
from pandaloginvestigator.core.utils import utils
import os
import time
import logging


logger = logging.getLogger(__name__)


def translate_logs(dir_pandalogs_path, dir_unpacked_path, syscall_dict, dir_translated_path, core_num, max_num=None):
    """
    Convert system call numbers into explicit system call names.
    Iterate through all the log files in the folder specified in the configuration. Generate equal lists of files to
    pass to worker_translator workers. The number of logs to translate is passed as argument, translate all logs file if
    max_num = None. Logs time spent in the process.

    :param dir_pandalogs_path:
    :param dir_unpacked_path:
    :param syscall_dict:
    :param dir_translated_path:
    :param core_num:
    :param max_num:
    :return:
    """
    logger.info('Starting translating operation with max_num = ' + str(max_num))
    t1 = time.time()
    filenames = sorted(utils.strip_filename_ext(os.listdir(dir_pandalogs_path)))
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    formatted_input = utils.format_worker_input(
        core_num,
        file_names_sublists,
        (
            dir_unpacked_path,
            dir_translated_path,
            syscall_dict
        )
    )
    pool = Pool(processes=core_num)
    pool.map(worker_translator.work, formatted_input)
    pool.close()
    t2 = time.time()
    logger.info('Total translating time: ' + str(t2 - t1))
