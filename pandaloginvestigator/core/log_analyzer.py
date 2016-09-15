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
def analyze_logs(dir_unpacked_path, dir_analyzed_path, dir_results_path, dir_database_path, core_num, max_num):
    logger.info('Starting analysis operation with max_num = ' + str(max_num))
    t1 = time.time()
    db_file_malware_name_map = db_manager.acquire_malware_file_dict(dir_database_path)
    filenames = sorted(os.listdir(dir_unpacked_path))
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    if len(file_names_sublists) != core_num:
        logger.error('ERROR: size of split workload different from number of cores')
    formatted_input = utils.format_worker_input(core_num, file_names_sublists, (db_file_malware_name_map, dir_unpacked_path, dir_analyzed_path))
    pool = Pool(processes=core_num)
    results = pool.map(worker_analyzer.work, formatted_input)
    pool.close()
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
