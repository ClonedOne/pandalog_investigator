import logging
from pandaloginvestigator.core.utils import panda_utils


logger = logging.getLogger(__name__)


# For each file in the filenames list, uses the 'pandalog_reader' tool inside
# panda to unpack it and save it to a separate folder.
def work(params_pack):
    worker_id = params_pack[0]
    filenames = params_pack[1]
    dir_pandalogs_path = params_pack[2]
    dir_unpacked_path = params_pack[3]
    dir_panda_path = params_pack[4]
    j = 0.0
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId = ' + str(worker_id) + ' unpacking ' + str(total_files) + ' log files')
    for filename in filenames:
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
        panda_utils.unpack_log(dir_panda_path, filename, dir_pandalogs_path, dir_unpacked_path)

