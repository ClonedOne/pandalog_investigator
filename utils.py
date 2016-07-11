import pprint
import os


def final_output(dir_project_path, malware_dict):
    res_file = open(dir_project_path + 'resfile.txt', 'w')
    for entry in malware_dict:
        res_file.write('File name: ' + entry + '\n\n')
        res_file.write(str(malware_dict[entry]) + '\n\n\n')


def output_on_file(filename, process_dict, inverted_process_dict, malwares, dir_analyzed_logs):
    outfile = open(dir_analyzed_logs + filename + '_a.txt', 'w')
    pprint.pprint(process_dict, outfile)
    outfile.write('\n')
    pprint.pprint(inverted_process_dict, outfile)
    outfile.write('\n')
    for malware in malwares:
        outfile.write(str(malware) + '\n\n')


def clean_log(filename, dir_unpacked_path):
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')


def get_new_path(words):
    line = ''
    fixed = 'name=['
    for word in words:
        line += word + ' '
    index = line.find(fixed)
    line = line[index:]
    return os.path.normpath(line.split('[')[1].replace(']', ''))
