import time
import os
from multiprocessing import Pool
from workers import worker_unpacker


def unpack_logs(dir_pandalogs_path, dir_panda_path, dir_unpacked_path, max_num, ):
    t1 = time.time()
    filenames = sorted(os.listdir(dir_pandalogs_path))
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
    pool.map(worker_unpacker.work, [(0, file_names_0, dir_pandalogs_path, dir_unpacked_path, dir_panda_path),
                                    (1, file_names_1, dir_pandalogs_path, dir_unpacked_path, dir_panda_path),
                                    (2, file_names_2, dir_pandalogs_path, dir_unpacked_path, dir_panda_path),
                                    (3, file_names_3, dir_pandalogs_path, dir_unpacked_path, dir_panda_path)])
    t2 = time.time()
    print 'Total unpacking time: ' + str(t2 - t1)
