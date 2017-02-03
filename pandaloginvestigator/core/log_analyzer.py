from multiprocessing import Pool
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.workers import worker_analyzer
from pandaloginvestigator.core.utils import db_manager
import time
import logging

logger = logging.getLogger(__name__)


def analyze_logs(dir_panda_path, dir_pandalogs_path, dir_unpacked_path, dir_analyzed_path,
                 dir_results_path, dir_database_path, core_num, max_num, small_disk):
    """
    Analyze each unpacked log file counting the number of instruction executed
    and identifying corrupted sub processes. Iterate through all the log files
    in the folder specified in the configuration. Generate equal lists of
    files to pass to worker_analyzer workers. The number of logs to analyze
    is passed as argument, analyze all logs file if max_num = None.
    Logs time spent in the process.

    :param dir_panda_path:
    :param dir_pandalogs_path:
    :param dir_unpacked_path:
    :param dir_analyzed_path:
    :param dir_results_path:
    :param dir_database_path:
    :param core_num:
    :param max_num:
    :param small_disk:
    :return:
    """
    logger.info('Starting analysis operation with max_num = ' + str(max_num))
    t1 = time.time()

    db_file_malware_name_map = db_manager.acquire_malware_file_dict(dir_database_path)
    filenames, max_num = utils.input_with_modifiers(dir_unpacked_path, dir_pandalogs_path, small_disk=small_disk,
                                                    max_num=max_num)
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    formatted_input = utils.format_worker_input(
        core_num,
        file_names_sublists,
        (
            db_file_malware_name_map,
            dir_unpacked_path,
            dir_analyzed_path,
            small_disk,
            dir_panda_path,
            dir_pandalogs_path
        )
    )
    pool = Pool(processes=core_num)
    results = pool.map(worker_analyzer.work, formatted_input)
    pool.close()

    db_file_malware_dict = {}
    file_corrupted_processes_dict = {}
    file_terminate_dict = {}
    file_sleep_dict = {}
    file_crash_dict = {}
    file_error_dict = {}
    file_writefile_dict = {}
    dict_list = [db_file_malware_dict,
                 file_corrupted_processes_dict,
                 file_terminate_dict,
                 file_sleep_dict,
                 file_crash_dict,
                 file_error_dict,
                 file_writefile_dict]
    utils.update_results(results, dict_list)

    file_utils.final_output_instructions(
        dir_results_path,
        filenames,
        db_file_malware_dict,
        file_corrupted_processes_dict,
        file_terminate_dict,
        file_sleep_dict,
        file_crash_dict,
        file_error_dict,
        file_writefile_dict
    )

    t2 = time.time()
    logger.info('Total analysis time: ' + str(t2 - t1))
