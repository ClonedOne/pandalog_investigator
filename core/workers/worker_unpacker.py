from core.utils import utils


def work(worker_id, filenames, dir_pandalogs_path, dir_unpacked_path, dir_panda_path):
    j = 0.0
    total_files = len(filenames)
    print 'Unpacking... WorkerId = ' + str(worker_id)
    os.chdir(dir_panda_path)
    for filename in filenames:
        j += 1
        print worker_id, str(j/total_files * 100) + '%'
        reduced_filename = filename[:-9]
        utils.unpack_log(filename, dir_pandalogs_path, dir_unpacked_path)