import os
from core.utils import utils


def work((worker_id, filenames, dir_pandalogs_path, dir_unpacked_path, dir_panda_path)):
    j = 0.0
    total_files = len(filenames)
    print 'WorkerId = ' + str(worker_id) + ' unpacking ' + str(total_files) + ' log files'
    os.chdir(dir_panda_path)
    for filename in filenames:
        j += 1
        print worker_id, str(j/total_files * 100) + '%'
        utils.unpack_log(filename, dir_pandalogs_path, dir_unpacked_path)