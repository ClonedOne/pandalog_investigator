from pandaloginvestigator.core.domain.corrupted_process_object import CorruptedProcess
from pandaloginvestigator.core.domain.sample_object import Sample
from pandaloginvestigator.core.io import file_input
from itertools import combinations
import matplotlib.pyplot as plt
from pprint import pprint
import networkx as nx
import jsonpickle
import json
import os


dir_vt_path = '/home/yogaub/projects/seminar/vt'
dir_database_path = '/home/yogaub/projects/seminar/database'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_results_path = '/home/yogaub/projects/seminar/created_dirs/dir_results'
dir_unpacked_path = '/home/yogaub/projects/seminar/created_dirs/dir_unpacked'
dir_analyzed_path = '/home/yogaub/projects/seminar/created_dirs/dir_analyzed'
core_num = 4


def main():
    available_uuid_path = os.path.join(dir_results_path, 'uuid_available.json')
    if os.path.isfile(available_uuid_path):
        with open(available_uuid_path, 'r', encoding='utf-8', errors='replace') as in_file:
            label_uuid = json.load(in_file)
    else:
        print('Available uuid file missing')
        return

    mydooms = sorted(label_uuid['mydoom'])[:10]

    mydooms_dict = {}
    for uuid in mydooms:
        mydooms_dict[uuid] = file_input.load_sample(uuid, dir_analyzed_path)

    for uuid, sample in mydooms_dict.items():
        for process_info, process in sample.corrupted_processes.items():
            pass


if __name__ == '__main__':
    main()
