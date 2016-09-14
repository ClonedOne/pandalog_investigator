import os
import time
import logging
from multiprocessing import Pool
from .workers import worker_translator


logger = logging.getLogger(__name__)


# Convert system call numbers into explicit system call names.
# Iterate through all the log files in the folder specified in the configuration. Generate equal lists of files to
# pass to worker_translator workers. The number of logs to translate is passed as argument, translate all logs file if
# max_num = None. Logs time spent in the process.
def translate_logs(dir_unpacked_path, syscall_dict, dir_translated_path, max_num=None):
    logger.info('Starting translating operation with max_num = ' + str(max_num))
    t1 = time.time()
    filenames = sorted(os.listdir(dir_unpacked_path))
    if not max_num:
        max_num = len(filenames)
    j = 0
    file_names_0 = []
    file_names_1 = []
    file_names_2 = []
    file_names_3 = []
    for filename in filenames:
        if j % 4 == 0:
            file_names_0.append(filename)
        elif j % 4 == 1:
            file_names_1.append(filename)
        elif j % 4 == 2:
            file_names_2.append(filename)
        else:
            file_names_3.append(filename)
        j += 1
        if j == max_num:
            break
    pool = Pool(processes=4)
    pool.map(worker_translator.work, [(0, file_names_0, dir_unpacked_path, dir_translated_path, syscall_dict),
                                      (1, file_names_1, dir_unpacked_path, dir_translated_path, syscall_dict),
                                      (2, file_names_2, dir_unpacked_path, dir_translated_path, syscall_dict),
                                      (3, file_names_3, dir_unpacked_path, dir_translated_path, syscall_dict)])
    pool.close()
    t2 = time.time()
    logger.info('Total translating time: ' + str(t2 - t1))
