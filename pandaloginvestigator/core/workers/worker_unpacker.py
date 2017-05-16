from pandaloginvestigator.core.utils import panda_utils
import logging

"""
Worker process in charge of unpacking the pandalog files.
"""

logger = logging.getLogger(__name__)


def work(params_pack):
    """
    For each file in the filenames list, uses the 'pandalog_reader' tool inside
    panda to unpack it and save it to a separate folder.

    :param params_pack:
    :return:
    """
    worker_id = params_pack[0]
    filenames = params_pack[1]
    dir_pandalogs_path = params_pack[2]
    dir_unpacked_path = params_pack[3]
    dir_panda_path = params_pack[4]
    j = 0.0
    total_files = len(filenames)
    logger.info('WorkerId = ' + str(worker_id) + ' unpacking ' + str(total_files) + ' log files')
    for filename in filenames:
        filename = filename + '.txz.plog' if filename[-5:] != '.plog' else filename
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
        panda_utils.unpack_log(dir_panda_path, filename, dir_pandalogs_path, dir_unpacked_path)
