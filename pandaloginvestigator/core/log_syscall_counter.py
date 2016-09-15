from pandaloginvestigator.core.utils import db_manager
from pandaloginvestigator.core.utils import syscalls_getter
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.workers import worker_syscall_counter
from multiprocessing import Pool
import os
import logging
import time

logger = logging.getLogger(__name__)


# Analyze each unpacked log file counting the number of system calls executed by malwares and corrupted processes.
# Iterate through all the log files in the folder specified in the configuration. Generate equal lists of files to
# pass to worker_syscall_counter workers. The number of logs to analyze is passed as argument, analyze all logs file if
# max_num = None. Logs time spent in the process.
def count_syscalls(dir_unpacked_path, dir_database_path, dir_results_path, core_num, max_num):
    logger.info('Starting system calls counting operation with max_num = ' + str(max_num))
    t1 = time.time()
    sys_call_dict = syscalls_getter.get_syscalls()
    db_file_malware_name_map = db_manager.acquire_malware_file_dict(dir_database_path)
    filenames = sorted(os.listdir(dir_unpacked_path))
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    if len(file_names_sublists) != core_num:
        logger.error('ERROR: size of split workload different from number of cores')
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, (dir_unpacked_path, sys_call_dict, db_file_malware_name_map))
    pool = Pool(processes=core_num)
    pool.map(worker_syscall_counter.work, formatted_input)
    t2 = time.time()
    logger.info('Total counting time: ' + str(t2 - t1))
