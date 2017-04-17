from pandaloginvestigator.core.io import results_reader
from pandaloginvestigator.core.io import db_manager
from collections import Counter
from pprint import pprint
import json
import os
import re

dir_vt_path = '/home/homeub/projects/investigator/vt'
dir_results_path = '/home/homeub/projects/investigator/created_dirs/dir_results'
dir_database_path = '/home/homeub/projects/investigator/database'

worker_id = 'test vt'
total_scans = 'total'
behavior = 'behaviour-v1'
info = 'additional_info'
file_sys = 'filesystem'
written = 'written'
threshold = 0.75


def main():
    print('Getting uuid indices')
    suspects_dict = results_reader.read_result_suspect(dir_results_path)
    print('Getting md5 indices')
    md5_index = map_to_md5(suspects_dict)
    print('Getting md5 labels')
    md5_label = get_sample_labels()
    print('Getting md5 with behavior')
    md5_behavior = get_number_behavior()
    print('Getting md5 non evasive')
    md5_non_evasive = get_non_evasive()

    md5_indexed_labeled = set(md5_index.keys()) & set(md5_label.keys())
    md5_indexed_labeled_behavior = md5_indexed_labeled & set(md5_behavior)
    md5_indexed_labeled_behavior_non_evasive = md5_indexed_labeled_behavior & set(md5_non_evasive)

    out_to_file('ind_lab_beh', list(md5_indexed_labeled_behavior))

    print('total suspects: {}'.format(len(suspects_dict)))
    print('total indexed: {}'.format(len(md5_index)))
    print('total vts: {}'.format(len(os.listdir(dir_vt_path))))
    print('total labeled: {}'.format(len(md5_label)))
    print('total with behavior: {}'.format(len(md5_behavior)))
    print('total non evasive: {}'.format(len(md5_non_evasive)))
    print('total indexed and labeled: {}'.format(len(md5_indexed_labeled)))
    print('total indexed and labeled with behavior: {}'.format(len(md5_indexed_labeled_behavior)))
    print('total indexed and labeled with behavior non evasive: {}'.format(len(md5_indexed_labeled_behavior_non_evasive)))

    exit()
    distribution = Counter(md5_index.values())
    pprint([(i, round(i[1] / float(len(md5_index)), 2) * 100.0) for i in distribution.most_common()])
    pprint(sum(float(i[0]) * i[1] for i in distribution.most_common()) / float(len(md5_index)))

    written_file_frequencies = Counter()
    runtime_dll_frequencies = Counter()
    dns_frequencies = Counter()
    index_frequencies = Counter()

    above_threshold = 0
    with_behavior = 0
    not_analyzed = 0
    analyzed = 0

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


def map_to_md5(suspects_dict):
    """
    Uses the database to build a dictionary mapping md5s to suspect indices, instead of files uuid.
    
    :param suspects_dict: dictionary mapping uuid to suspects
    :return: dictionary mapping md5 to suspects
    """

    md5_index_map = {}
    collisions = set()
    uuid_md5_map = db_manager.acquire_malware_file_dict_full(dir_database_path)

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
    file_name = 'av_labels'
    file_path = os.path.join(dir_results_path, file_name + '.json')

    # Checks if labels file is already available
    if os.path.isfile(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='replace') as in_file:
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

    out_to_file(file_name, md5_labels)
    return md5_labels


def get_number_behavior():
    """
    Retrieves the list of VT reports containing the behavior field.
    Generates a json file containing the list to speed up successive calls. 
    
    :return: list of md5s
    """

    file_name = 'with_behavior'
    file_path = os.path.join(dir_results_path, file_name + '.json')
    md5s = []

    # Checks if labels file is already available
    if os.path.isfile(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='replace') as in_file:
            md5s = json.load(in_file)
        return md5s

    for md5 in sorted(os.listdir(dir_vt_path)):
        json_report = json.loads(open(os.path.join(dir_vt_path, md5)).read())
        if behavior in json_report[info]:
            md5s.append(md5)

    out_to_file(file_name, md5s)
    return md5s


def get_non_evasive():
    """
    Examines the VT reports looking for those samples which are identified by a large number of the AVs.
    Returns a list of probably non evasive samples.
    Generates a json file containing the list to speed up successive calls.
    
    :return: list of md5s
    """

    file_name = 'non_evasive'
    file_path = os.path.join(dir_results_path, file_name + '.json')
    md5s = []

    # Checks if labels file is already available
    if os.path.isfile(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='replace') as in_file:
            md5s = json.load(in_file)
        return md5s

    for md5 in sorted(os.listdir(dir_vt_path)):
        json_report = json.loads(open(os.path.join(dir_vt_path, md5)).read())
        positives = float(json_report['positives'])
        scans = float(json_report['total'])
        identification_percentage = positives / scans

        if identification_percentage >= threshold:
            md5s.append(md5)

    out_to_file(file_name, md5s)
    return md5s


def out_to_file(f_name, data):
    """
    Outputs to file the specified data.
    
    :param f_name: name of the file to create
    :param data: data to output
    :return: 
    """

    with open(os.path.join(dir_results_path, f_name + '.json'), 'w', encoding='utf-8', errors='replace') as out_file:
        json.dump(data, out_file, indent=2)


if __name__ == '__main__':
    main()
