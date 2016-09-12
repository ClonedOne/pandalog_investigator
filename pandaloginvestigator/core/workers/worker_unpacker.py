import os
import logging
from pandaloginvestigator.core.utils import utils


logger = logging.getLogger(__name__)


# For each file in the filenames list, uses the 'pandalog_reader' tool inside panda to unpack it and save it to a
# separate folder.
def work((worker_id, filenames, dir_pandalogs_path, dir_unpacked_path, dir_panda_path)):
    j = 0.0
    total_files = len(filenames)
    logger.info('WorkerId = ' + str(worker_id) + ' unpacking ' + str(total_files) + ' log files')
    os.chdir(dir_panda_path)
    for filename in filenames:
        j += 1
        logger.info(str(worker_id) + ' ' + str(j/total_files * 100) + '%')
        utils.unpack_log(filename, dir_pandalogs_path, dir_unpacked_path)