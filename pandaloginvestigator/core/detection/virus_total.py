from pandaloginvestigator.core.io import results_reader
from pandaloginvestigator.core.io import db_manager
from collections import Counter
from pprint import pprint
import json
import os

# dir_vt_path = '/home/homeub/projects/investigator/vt'
dir_vt_path = '/home/yogaub/projects/seminar/vt'
dir_results_path = '/home/yogaub/projects/seminar/created_dirs/dir_results'
dir_database_path = '/home/yogaub/projects/seminar/database'

worker_id = 'test vt'
positive_identification = 'positives'
total_scans = 'total'
behavior = 'behaviour-v1'
info = 'additional_info'
file_sys = 'filesystem'
written = 'written'
threshold = 0.9


def main():
    suspects_dict = results_reader.read_result_suspect(dir_results_path)
    md5_index = map_to_md5(suspects_dict)
    total_files = len(os.listdir(dir_vt_path))

    written_file_frequencies = Counter()
    runtime_dll_frequencies = Counter()
    dns_frequencies = Counter()
    index_frequencies = Counter()

    above_threshold = 0
    with_behavior = 0
    not_analyzed = 0
    j = 0.0

    for file_name in sorted(os.listdir(dir_vt_path)):
        json_report = json.loads(open(os.path.join(dir_vt_path, file_name)).read())

        positives = float(json_report[positive_identification])
        scans = float(json_report[total_scans])
        identification_percentage = positives / scans

        if identification_percentage >= threshold:
            above_threshold += 1

            if file_name in md5_index:
                index_frequencies[md5_index[file_name]] += 1
            else:
                not_analyzed += 1

            if behavior in json_report[info]:
                with_behavior += 1

                files_written = json_report[info][behavior][file_sys][written]
                runtime_dlls = json_report[info][behavior]['runtime-dlls']
                dns = json_report[info][behavior]['network']['dns']

                if files_written:
                    for file_written in files_written:
                        written_file_frequencies[file_written['path']] += 1

                if runtime_dlls:
                    for runtime_dll in runtime_dlls:
                        runtime_dll_frequencies[runtime_dll['file']] += 1

                if dns:
                    for entry in dns:
                        dns_frequencies[(entry['ip'], entry['hostname'])] += 1

        j += 1
        # if j % 100 == 0:
        #     print('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))

    pprint('Above threshold: {}'.format(above_threshold))
    pprint('With behavior: {}'.format(with_behavior))
    pprint('Not analyzed: {}'.format(not_analyzed))
    # pprint(written_file_frequencies.most_common(100))
    # pprint(runtime_dll_frequencies.most_common(100))
    # pprint(dns_frequencies.most_common(100))
    pprint(index_frequencies.most_common(20))


def out_file_names(file_list, label):
    with open(label, 'w', encoding='utf-8', errors='replace') as out_file:
        for file_name in file_list:
            out_file.write(file_name + '\n')


def map_to_md5(suspects_dict):
    """
    Uses the database to build a dictionary mapping md5s to suspect indices, instead of files uuid.
    
    :param suspects_dict: dictionary mapping uuid to suspects
    :return: dictionary mapping md5 to suspects
    """

    md5_index_map = {}
    uuid_md5_map = db_manager.acquire_malware_file_dict_full(dir_database_path)

    for uuid, index in suspects_dict.items():
        md5 = uuid_md5_map[uuid]
        md5_index_map[md5] = index

    return md5_index_map


if __name__ == '__main__':
    main()
