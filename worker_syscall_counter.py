import os
import utils


dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'

unpack_command = './pandalog_reader'
system_call_id = u'(num='
context_switch = u'new_pid,'


def work((worker_id, filenames, sys_call_dict, filename_malware_dict)):
    os.chdir(dir_panda_path)
    j = 0.0
    num_files = len(filenames)
    print worker_id, num_files
    filename_syscall_dict = {}
    for filename in filenames:
        j += 1
        print worker_id, j / num_files
        extended_filename = filename + '.txz.plog'
        utils.unpack_log(extended_filename, unpack_command, dir_pandalogs_path, dir_unpacked_path)
        filename_syscall_dict[filename] = count_syscalls(filename, sys_call_dict, filename_malware_dict)
        utils.clean_log(extended_filename, dir_unpacked_path)
    return filename_syscall_dict


def count_syscalls(filename, sys_call_dict, filename_malware_dict):
    malware_syscall_dict = {}
    malwares = filename_malware_dict[filename]
    active_mal = None
    with open(dir_unpacked_path + filename + '.txz.plog.txt', 'r') as logfile:
        for line in logfile:
            line = unicode(line, errors='ignore')
            if context_switch in line:
                commas = line.strip().split(',')
                pid = int(commas[2].strip())
                proc_name = commas[3].split(')')[0].strip()
                if (proc_name, pid) in malwares:
                    active_mal = proc_name
                else:
                    active_mal = None
            elif active_mal and system_call_id in line:
                pos = line.find(system_call_id)
                sys_call_num = int(line[pos + 5:].split(')')[0])
                if sys_call_num in sys_call_dict:
                    # print sys_call_num, "Sys call number not found"
                    sys_call = sys_call_dict[sys_call_num]
                else:
                    sys_call = str(sys_call_num)
                malware_syscall_dict[sys_call] = malware_syscall_dict.get(sys_call, 0) + 1
    return malware_syscall_dict
