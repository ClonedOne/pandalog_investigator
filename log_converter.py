import os
import ast
import utils
import codecs

dir_project_path = '/home/yogaub/projects/seminar/'
dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_malware_db = '/home/yogaub/projects/seminar/database'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_resfile_path = '/home/yogaub/Desktop/resfile.txt'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_convert_path = '/home/yogaub/projects/seminar/converted/'
dir_sys_call_table = '/home/yogaub/projects/seminar/'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'

unpack_command = './pandalog_reader'
empty_list = 'Final instruction count: 	[0, 0, 0, 0]'
system_call_id = u'(num='
context_switch = u'new_pid,'


def acquire_interesting(interesting_dict, threshold, size, conv_all=False):
    next_file_name = True
    next_values = False
    with open(dir_resfile_path, 'r') as resfile:
        last_file_name = ''
        for line in resfile:
            line = line.strip()
            if not line:
                next_file_name = True
                continue
            if next_file_name:
                filename = line.split()[2]
                last_file_name = filename
                next_file_name = False
                next_values = True
                continue
            if next_values:
                if line != empty_list:
                    values = line.split('\t')[1].replace('[', '').replace(']', '').replace(',', '').split()
                    instruction_executed = int(values[3])
                    if conv_all:
                        interesting_dict[last_file_name] = instruction_executed
                    if instruction_executed < threshold:
                        values = next(resfile).split('\t')
                        terminating = ast.literal_eval(values[1].strip())
                        sleeping = ast.literal_eval(values[3].strip())
                        crashing = ast.literal_eval(values[5].strip())
                        error = ast.literal_eval(values[7].strip())
                        if not error and not crashing and len(interesting_dict) < size and (terminating or sleeping):
                            interesting_dict[last_file_name] = instruction_executed
                next_values = False
                continue


def convert(filename, sys_call_dict, filename_malware_dict):
    malwares = filename_malware_dict[filename]
    active_mal = None
    with open(dir_unpacked_path + filename + '.txz.plog.txt', 'r') as logfile:
        with codecs.open(dir_convert_path + filename + '_c.txt', 'w', 'utf-8') as conv_file:
            for line in logfile:
                line = unicode(line, errors='ignore')
                if context_switch in line:
                    commas = line.strip().split(',')
                    pid = int(commas[2].strip())
                    proc_name = commas[3].split(')')[0].strip()
                    if (proc_name, pid) in malwares:
                        active_mal = proc_name
                        conv_file.write('\n' + line + '\n')
                    else:
                        active_mal = None
                elif active_mal and system_call_id in line:
                    pos = line.find(system_call_id)
                    sys_call_num = int(line[pos + 5:].split(')')[0])
                    if sys_call_num not in sys_call_dict:
                        continue
                    sys_call = sys_call_dict[sys_call_num]
                    conv_file.write(sys_call + '\n')
                elif active_mal:
                    conv_file.write('\n' + line + '\n')


def acquire_sys_calls(sys_call_dict):
    with open(dir_sys_call_table + 'sys_tab.txt') as tabfile:
        for line in tabfile:
            line = line.split()
            if len(line) > 1:
                sys_call_dict[int(line[1], 16)] = line[0]


def acquire_filename_malware(interesting_dict, filename_malware_dict):
    for filename in interesting_dict.keys():
        filename_malware_dict[filename] = []
        with open(dir_analyzed_logs + filename + '_a.txt') as a_file:
            for line in a_file:
                if 'Malware name:' in line:
                    last_mal = line.split(':')[1].strip()
                if 'Malware pid:' in line:
                    pid = int(line.split()[2].strip())
                    filename_malware_dict[filename].append((last_mal, pid))


def main():
    interesting_dict = {}
    sys_call_dict = {}
    filename_malware_dict = {}
    size = 3000
    conv_all = False
    acquire_sys_calls(sys_call_dict)
    acquire_interesting(interesting_dict, 8000000000, size, conv_all=conv_all)
    acquire_filename_malware(interesting_dict, filename_malware_dict)
    print len(sys_call_dict)
    print len(filename_malware_dict)
    os.chdir(dir_panda_path)
    items = len(interesting_dict)
    j = 0.0
    for filename in interesting_dict.keys():
        print j / items * 100, '%'
        extended_filename = filename + '.txz.plog'
        utils.unpack_log(extended_filename, unpack_command, dir_pandalogs_path, dir_unpacked_path)
        convert(filename, sys_call_dict, filename_malware_dict)
        utils.clean_log(extended_filename, dir_unpacked_path)
        j += 1


if __name__ == '__main__':
    main()