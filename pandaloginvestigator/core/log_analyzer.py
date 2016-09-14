from multiprocessing import Pool
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.workers import worker_analyzer
from pandaloginvestigator.core.utils import db_manager
import os
import time
import logging


logger = logging.getLogger(__name__)


# Analyze each unpacked log file counting the number of instruction executed and identifying corrupted subprocesses.
# Iterate through all the log files in the folder specified in the configuration. Generate equal lists of files to
# pass to worker_analyzer workers. The number of logs to analyze is passed as argument, analyze all logs file if
# max_num = None. Logs time spent in the process.
def analyze_logs(dir_unpacked_path, dir_analyzed_path, dir_results_path, dir_database_path, max_num):
    logger.info('Starting analysis operation with max_num = ' + str(max_num))
    t1 = time.time()
    db_file_malware_name_map = db_manager.acquire_malware_file_dict(dir_database_path)
    filenames = sorted(os.listdir(dir_unpacked_path))
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
    results = pool.map(worker_analyzer.work, [(0, file_names_0, db_file_malware_name_map, dir_unpacked_path, dir_analyzed_path),
                                              (1, file_names_1, db_file_malware_name_map, dir_unpacked_path, dir_analyzed_path),
                                              (2, file_names_2, db_file_malware_name_map, dir_unpacked_path, dir_analyzed_path),
                                              (3, file_names_3, db_file_malware_name_map, dir_unpacked_path, dir_analyzed_path)])
    db_file_malware_dict = {}
    file_corrupted_processes_dict = {}
    file_terminate_dict = {}
    file_sleep_dict = {}
    file_crash_dict = {}
    file_error_dict = {}
    dict_list = [db_file_malware_dict,
                 file_corrupted_processes_dict,
                 file_terminate_dict,
                 file_sleep_dict,
                 file_crash_dict,
                 file_error_dict]
    res = utils.update_results(results, dict_list)
    if res < 0:
        logger.error('ERROR: analyze_logs failed update_results()')
        return
    utils.final_output(dir_results_path,
                       filenames,
                       db_file_malware_dict,
                       file_corrupted_processes_dict,
                       file_terminate_dict,
                       file_sleep_dict,
                       file_crash_dict,
                       file_error_dict)
    t2 = time.time()
    logger.info('Total analysis time: ' + str(t2 - t1))
