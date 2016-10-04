from multiprocessing import Pool
from pandaloginvestigator.core.workers import worker_unpacker
from pandaloginvestigator.core.utils import utils
import os
import time
import logging


logger = logging.getLogger(__name__)


# Unpack the compressed logs. Iterate through all the log files in the folder
# specified in the configuration. Generate equal lists of files to pass to
# worker_unpack workers. The number of logs to unpack is passed as argument,
# unpack all logs file if max_num = None. Logs time spent unpacking.
def unpack_logs(dir_pandalogs_path, dir_panda_path, dir_unpacked_path, core_num, file_list=None, max_num=None):
    logger.info('Starting unpacking operation with max_num = ' + str(max_num))
    t1 = time.time()
    if file_list:
        filenames = []
        with open(file_list, 'r', encoding='utf-8', errors='replace') as list_file:
            for line in list_file:
                filenames.append(line.strip())
    else:
        filenames = sorted(os.listdir(dir_pandalogs_path))
    if max_num:
        max_num = int(max_num)
    else:
        max_num = len(filenames)
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    formatted_input = utils.format_worker_input(core_num, file_names_sublists,
                    (dir_pandalogs_path, dir_unpacked_path, dir_panda_path))
    pool = Pool(processes=core_num)
    pool.map(worker_unpacker.work, formatted_input)
    pool.close()
    t2 = time.time()
    logger.info('Total unpacking time: ' + str(t2 - t1))
