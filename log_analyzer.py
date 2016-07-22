import os
import db_manager
import worker
import utils
import time
from multiprocessing import Pool

dir_project_path = '/home/yogaub/projects/seminar/'
dir_malware_db = '/home/yogaub/projects/seminar/database'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'


def update_results(results, db_file_malware_dict, file_corrupted_processes_dict, file_terminate_dict, file_sleep_dict):
    for sub_res in results:
        db_file_malware_dict.update(sub_res[0])
        file_corrupted_processes_dict.update(sub_res[1])
        file_terminate_dict.update(sub_res[2])
        file_sleep_dict.update(sub_res[3])


# Each file has to be unpacked using the PANDA tool
# Analyze each unpacked log file calling analyze_log()
# Since the size of the unpacked logs may engulf the disk, delete the file after the process
def main():
    db_file_malware_name_map = db_manager.acquire_malware_file_dict()
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
    t1 = time.time()
    pool = Pool(processes=4)
    results = pool.map(worker.work, [(0, file_names_0, db_file_malware_name_map),
                                     (1, file_names_1, db_file_malware_name_map),
                                     (2, file_names_2, db_file_malware_name_map),
                                     (3, file_names_3, db_file_malware_name_map)])

    db_file_malware_dict = {}
    file_corrupted_processes_dict = {}
    file_terminate_dict = {}
    file_sleep_dict = {}
    update_results(results, db_file_malware_dict, file_corrupted_processes_dict, file_terminate_dict, file_sleep_dict)
    utils.final_output(dir_project_path, filenames, db_file_malware_dict, file_corrupted_processes_dict, file_terminate_dict, file_sleep_dict)
    t2 = time.time()
    print t2-t1


if __name__ == '__main__':
    main()
