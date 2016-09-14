from multiprocessing import Pool
from pandaloginvestigator.core.workers import worker_unpacker
from pandaloginvestigator.core.utils import utils
import os
import time
import logging


logger = logging.getLogger(__name__)


# Unpack the compressed logs.
# Iterate through all the log files in the folder specified in the configuration. Generate equal lists of files to
# pass to worker_unpack workers. The number of logs to unpack is passed as argument, unpack all logs file if
# max_num = None. Logs time spent unpacking.
def unpack_logs(dir_pandalogs_path, dir_panda_path, dir_unpacked_path, core_num, max_num=None):
    logger.info('Starting unpacking operation with max_num = ' + str(max_num))
    t1 = time.time()
    filenames = sorted(os.listdir(dir_pandalogs_path))
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    if len(file_names_sublists) != core_num:
        logger.error('ERROR: size of split workload different from number of cores')
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, (dir_pandalogs_path, dir_unpacked_path, dir_panda_path))
    pool = Pool(processes=core_num)
    pool.map(worker_unpacker.work, formatted_input)
    pool.close()
    t2 = time.time()
    logger.info('Total unpacking time: ' + str(t2 - t1))
