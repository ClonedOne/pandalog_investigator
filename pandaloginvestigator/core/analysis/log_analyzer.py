import logging
import time
from multiprocessing import Pool

from pandaloginvestigator.core.io import file_output, db_manager
from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.workers import worker_analyzer

logger = logging.getLogger(__name__)


def analyze_logs(dir_panda_path, dir_pandalogs_path, dir_unpacked_path, dir_analyzed_path,
                 dir_results_path, dir_database_path, core_num, max_num, small_disk):
    """
    Analyzes each pandalog file. 
    Iterates through all the log files in the folder specified in the configuration.
    Generates equal lists of files to pass to worker_analyzer workers.
    The number of logs to analyze is passed as argument, analyze all logs file if max_num = None.
    Logs time spent in the process.

    :param dir_panda_path: path to the pandalog unpacker tool
    :param dir_pandalogs_path: path to the pandalogs
    :param dir_unpacked_path: path to the unpacked pandalogs
    :param dir_analyzed_path: path to the analysis results
    :param dir_results_path: path to the global result folder
    :param dir_database_path: path to the database
    :param core_num: number of available CPU cores (as per configuration)
    :param max_num: the number of pandalogs to analyze
    :param small_disk: flag, if set unpacked pandalogs must be removed after use
    :return:
    """

    logger.info('Starting analysis operation with max_num = ' + str(max_num))
    t1 = time.time()

    db_file_malware_name_map = db_manager.acquire_malware_file_dict(dir_database_path)
    sys_call_dict = domain_utils.get_syscalls()

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
            dir_pandalogs_path,
            sys_call_dict
        )
    )
    pool = Pool(processes=core_num)
    results = pool.map(worker_analyzer.work, formatted_input)
    pool.close()
    pool.join()

    sample_dict = {}
    utils.update_results(results, sample_dict)

    file_output.final_output_analysis(sample_dict, dir_results_path)

    t2 = time.time()
    logger.info('Total analysis time: ' + str(t2 - t1))
