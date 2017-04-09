from collections import Counter
from pprint import pprint
import json
import os

dir_vt = '/home/homeub/projects/investigator/vt'

worker_id = 'test vt'
positive_identification = 'positives'
total_scans = 'total'
behavior = 'behaviour-v1'
info = 'additional_info'
file_sys = 'filesystem'
written = 'written'
file_path = 'path'
threshold = 0.9


def main():
    total_files = len(os.listdir(dir_vt))
    written_file_frequencies = Counter()
    runtime_dll_frequencies = Counter()
    above_threshold = 0
    with_behavior = 0
    j = 0.0

    for file_name in sorted(os.listdir(dir_vt)):
        json_report = json.loads(open(os.path.join(dir_vt, file_name)).read())

        positives = float(json_report[positive_identification])
        scans = float(json_report[total_scans])
        identification_percentage = positives / scans

        if identification_percentage >= threshold:
            above_threshold += 1

            if behavior in json_report[info]:
                with_behavior += 1

                files_written = json_report[info][behavior][file_sys][written]
                runtime_dlls = json_report[info][behavior]['runtime-dlls']

                if files_written:
                    for file_written in files_written:
                        written_file_frequencies[file_written[file_path]] += 1

                if runtime_dlls:
                    for runtime_dll in runtime_dlls:
                        runtime_dll_frequencies[runtime_dll['file']] += 1

        j += 1
        if j % 100 == 0:
            print('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))

    pprint('Above threshold: {}'.format(above_threshold))
    pprint('With behavior: {}'.format(with_behavior))
    pprint(written_file_frequencies.most_common(100))
    pprint(runtime_dll_frequencies.most_common(100))


def out_file_names(file_list, label):
    with open(label, 'w', encoding='utf-8', errors='replace') as out_file:
        for file_name in file_list:
            out_file.write(file_name + '\n')


if __name__ == '__main__':
    main()
