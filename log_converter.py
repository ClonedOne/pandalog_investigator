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
dir_convert = '/home/yogaub/projects/seminar/converted/'
dir_sys_call_table = '/home/yogaub/projects/seminar/'

unpack_command = './pandalog_reader'
empty_list = 'Final instruction count: 	[0, 0, 0, 0]'
system_call_index = u'(num='


def acquire_interesting(interesting_dict, threshold, size):
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
                    if instruction_executed < threshold:
                        values = next(resfile).split('\t')
                        terminating = ast.literal_eval(values[1].strip())
                        sleeping = ast.literal_eval(values[3].strip())
                        crashing = ast.literal_eval(values[5].strip())
                        error = ast.literal_eval(values[7].strip())
                        if not error and not crashing and len(interesting_dict) < size:
                            interesting_dict[last_file_name] = instruction_executed
                next_values = False
                continue


def convert(filename, sys_call_dict):
    with open(dir_unpacked_path + filename + '.txz.plog.txt', 'r') as logfile:
        with codecs.open(dir_convert + filename + '_c.txt', 'w', 'utf-8') as conv_file:
            for line in logfile:
                line = unicode(line, errors='ignore')
                if system_call_index in line:
                    pos = line.find(system_call_index)
                    sys_call_num = int(line[pos + 5:].split(')')[0])
                    if sys_call_num not in sys_call_dict:
                        continue
                    sys_call = sys_call_dict[sys_call_num]
                    conv_file.write(sys_call + '\n')
                else:
                    conv_file.write('\n' + line + '\n')


def acquire_sys_calls(sys_call_dict):
    with open(dir_sys_call_table + 'sys_tab.txt') as tabfile:
        for line in tabfile:
            line = line.split()
            if len(line) == 3:
                sys_call_dict[int(line[2], 16)] = line[0]


def main():
    interesting_dict = {}
    sys_call_dict = {}
    size = 10
    acquire_sys_calls(sys_call_dict)
    acquire_interesting(interesting_dict, 8000000, size)
    os.chdir(dir_panda_path)
    j = 0.0
    for filename in interesting_dict.keys():
        print j / size * 100, '%'
        extended_filename = filename + '.txz.plog'
        utils.unpack_log(extended_filename, unpack_command, dir_pandalogs_path, dir_unpacked_path)
        convert(filename, sys_call_dict)
        utils.clean_log(extended_filename, dir_unpacked_path)
        j += 1


if __name__ == '__main__':
    main()