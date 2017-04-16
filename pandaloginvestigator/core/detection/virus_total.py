from pandaloginvestigator.core.io import results_reader
from pandaloginvestigator.core.io import db_manager
from collections import Counter
from pprint import pprint
import json
import os
import re

# dir_vt_path = '/home/homeub/projects/investigator/vt'
dir_vt_path = '/home/homeub/projects/investigator/vt'
dir_results_path = '/home/homeub/projects/investigator/created_dirs/dir_results'
dir_database_path = '/home/homeub/projects/investigator/database'

worker_id = 'test vt'
total_scans = 'total'
behavior = 'behaviour-v1'
info = 'additional_info'
file_sys = 'filesystem'
written = 'written'
threshold = 0.9


def main():
    suspects_dict = results_reader.read_result_suspect(dir_results_path)
    md5_index = map_to_md5(suspects_dict)
    print('total suspects: {}'.format(len(suspects_dict)))
    print('total md5: {}'.format(len(md5_index)))
    print('total vts: {}'.format(len(os.listdir(dir_vt_path))))

    md5_label = get_sample_labels()
    print(len(md5_label))

    exit()
    distribution = Counter(md5_index.values())
    # pprint(distribution)
    pprint([(i, round(i[1] / float(len(md5_index)), 2) * 100.0) for i in distribution.most_common()])
    pprint(sum(float(i[0]) * i[1] for i in distribution.most_common()) / float(len(md5_index)))
    # pprint([(i, i[1] / float(len(md5_index)) * 100.0) for i in distribution.most_common()])

    written_file_frequencies = Counter()
    runtime_dll_frequencies = Counter()
    dns_frequencies = Counter()
    index_frequencies = Counter()

    above_threshold = 0
    with_behavior = 0
    not_analyzed = 0
    analyzed = 0
    j = 0.0

    for file_name in sorted(os.listdir(dir_vt_path)):
        json_report = json.loads(open(os.path.join(dir_vt_path, file_name)).read())

        positives = float(json_report['positives'])
        scans = float(json_report[total_scans])
        identification_percentage = positives / scans

        if identification_percentage >= threshold:
            above_threshold += 1

            if file_name in md5_index:
                analyzed += 1
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

    pprint('Above threshold: {}'.format(above_threshold))
    pprint('With behavior: {}'.format(with_behavior))
    pprint('Analyzed: {}'.format(analyzed))
    pprint('Not analyzed: {}'.format(not_analyzed))
    # pprint(written_file_frequencies.most_common(100))
    # pprint(runtime_dll_frequencies.most_common(100))
    # pprint(dns_frequencies.most_common(100))
    # pprint(index_frequencies.most_common())
    pprint([(i, round(i[1] / float(analyzed), 2) * 100.0) for i in index_frequencies.most_common()])
    pprint(sum(float(i[0]) * i[1] for i in index_frequencies.most_common()) / float(analyzed))


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
    collisions = set()
    uuid_md5_map = db_manager.acquire_malware_file_dict_full(dir_database_path)
    print(len(suspects_dict), len(uuid_md5_map))

    for uuid, index in suspects_dict.items():
        md5 = uuid_md5_map[uuid]
        if md5 in md5_index_map:
            collisions.add(md5)
        md5_index_map[md5] = index

    for md5 in collisions:
        md5_index_map.pop(md5, None)

    return md5_index_map


def get_sample_labels():
    """
    Examines the VirusTotal reports looking for the labels assigned to the sample by a subset of the most famous AVs.
    If the majority reach consensus on the family of the malicious software, adds it to a md5-family mapping.
    Generates a json file containing the dictionary to speed up successive calls. 
    
    :return: dictionary mapping md5s to malware family names
    """

    # For each AV this dictionary contains:
    #  * the regex pattern used to split the full label
    #  * the position of the malware family name in the split
    avs = {
        'Kaspersky': ('[\.!]', 2),
        'Symantec': ('[\.!]', 1),
        'Microsoft': ('[\./!:]', 2),
        'Avast': ('[-:\s]', 1),
        'TrendMicro': ('[\._]', 1)
    }
    majority = (len(avs) // 2) + 1
    md5_labels = {}

    # Checks if labels file is already available
    if os.path.isfile('av_labels.json'):
        with open('av_labels.json', 'r', encoding='utf-8', errors='replace') as in_file:
            md5_labels = json.load(in_file)
        return md5_labels

    # Otherwise retrieves the labels
    for md5 in sorted(os.listdir(dir_vt_path)):
        json_report = json.loads(open(os.path.join(dir_vt_path, md5)).read())
        label_counter = Counter()

        for av in json_report['scans']:
            if av in avs:
                result = json_report['scans'][av]['result']
                split = list(filter(None, re.split(avs[av][0], result) if result else []))
                mal_family = (split[avs[av][1]]).strip().lower() if len(split) > avs[av][1] else None
                if mal_family:
                    label_counter[mal_family] += 1

        if label_counter and label_counter.most_common(1)[0][1] >= majority:
            md5_labels[md5] = label_counter.most_common(1)[0][0]

    with open('av_labels.json', 'w', encoding='utf-8', errors='replace') as out_file:
        json.dump(md5_labels, out_file, indent=2)

    return md5_labels

if __name__ == '__main__':
    main()
