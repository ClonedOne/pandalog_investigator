from pandaloginvestigator.core.workers import worker_unpacker
from pandaloginvestigator.core.utils import utils
from multiprocessing import Pool
import logging
import time

logger = logging.getLogger(__name__)


def unpack_logs(dir_pandalogs_path, dir_panda_path, dir_unpacked_path, core_num, file_list=None, max_num=None):
    """
    Unpack the compressed logs. Iterate through all the log files in the folder
    specified in the configuration. Generate equal lists of files to pass to
    worker_unpack workers. The number of logs to unpack is passed as argument,
    unpack all logs file if max_num = None. Logs time spent unpacking.

    :param dir_pandalogs_path:
    :param dir_panda_path:
    :param dir_unpacked_path:
    :param core_num:
    :param file_list:
    :param max_num:
    :return:
    """
    logger.info('Starting unpacking operation with max_num = ' + str(max_num))
    t1 = time.time()
    filenames, max_num = utils.input_with_modifiers(dir_unpacked_path, dir_pandalogs_path, file_list=file_list,
                                                    max_num=max_num, unpacking=True)
    file_names_sublists = utils.divide_workload(filenames, core_num, max_num)
    formatted_input = utils.format_worker_input(
        core_num,
        file_names_sublists,
        (
            dir_pandalogs_path,
            dir_unpacked_path,
            dir_panda_path
        )
    )
    pool = Pool(processes=core_num)
    pool.map(worker_unpacker.work, formatted_input)
    pool.close()
    pool.join()
    t2 = time.time()
    logger.info('Total unpacking time: ' + str(t2 - t1))
