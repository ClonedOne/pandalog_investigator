from multiprocessing import Pool
from pandaloginvestigator.core.workers import worker_translator
from pandaloginvestigator.core.utils import utils
import os
import time
import logging


logger = logging.getLogger(__name__)


# Convert system call numbers into explicit system call names.
# Iterate through all the log files in the folder specified in the configuration. Generate equal lists of files to
# pass to worker_translator workers. The number of logs to translate is passed as argument, translate all logs file if
# max_num = None. Logs time spent in the process.
def translate_logs(dir_unpacked_path, syscall_dict, dir_translated_path, core_num, max_num=None):
    logger.info('Starting translating operation with max_num = ' + str(max_num))
    t1 = time.time()
    filenames = sorted(os.listdir(dir_unpacked_path))
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    if len(file_names_sublists) != core_num:
        logger.error('ERROR: size of split workload different from number of cores')
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, (dir_unpacked_path, dir_translated_path, syscall_dict))
    pool = Pool(processes=core_num)
    pool.map(worker_translator.work, formatted_input)
    pool.close()
    t2 = time.time()
    logger.info('Total translating time: ' + str(t2 - t1))
