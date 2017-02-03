from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import db_manager
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.workers import worker_syscall_counter
from multiprocessing import Pool
import logging
import time

logger = logging.getLogger(__name__)


def count_syscalls(dir_panda_path, dir_pandalogs_path, dir_unpacked_path, dir_database_path,
                   dir_results_path, dir_syscall_path, core_num, max_num, small_disk):
    """
    Analyze each unpacked log file counting the number of system calls executed
    by malwares and corrupted processes. Iterate through all the log files in
    the folder specified in the configuration. Generate equal lists of files to
    pass to worker_syscall_counter workers. The number of logs to analyze is
    passed as argument, analyze all logs file if max_num = None. Logs time spent
    in the process.

    :param dir_panda_path:
    :param dir_pandalogs_path:
    :param dir_unpacked_path:
    :param dir_database_path:
    :param dir_results_path:
    :param dir_syscall_path:
    :param core_num:
    :param max_num:
    :param small_disk:
    :return:
    """
    logger.info('Starting system calls counting operation with max_num = ' + str(max_num))
    t1 = time.time()

    sys_call_dict = domain_utils.get_syscalls()
    db_file_malware_name_map = db_manager.acquire_malware_file_dict(dir_database_path)
    filenames, max_num = utils.input_with_modifiers(dir_unpacked_path, dir_pandalogs_path, small_disk=small_disk,
                                                    max_num=max_num)

    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    formatted_input = utils.format_worker_input(
        core_num,
        file_names_sublists,
        (
            dir_unpacked_path,
            dir_syscall_path,
            sys_call_dict,
            db_file_malware_name_map,
            small_disk,
            dir_panda_path,
            dir_pandalogs_path
        )
    )
    pool = Pool(processes=core_num)
    results = pool.map(worker_syscall_counter.work, formatted_input)
    pool.close()

    filename_syscall_dict = {}
    dict_list = [filename_syscall_dict, ]
    utils.update_results(results, dict_list)

    file_utils.final_output_syscall(
        dir_results_path,
        filenames,
        filename_syscall_dict
    )

    t2 = time.time()
    logger.info('Total counting time: ' + str(t2 - t1))
