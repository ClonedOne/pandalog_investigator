import os
import subprocess
import pprint
import sys

dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'

unpack_command = './pandalog_reader'
new_proc = 'new_pid,'
termination_instruction = 'num=369)'
termination_dict = {}


def unpack_log(filename):
    sys.stdout = sys.__stdout__
    print 'unpacking: ' + filename
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + filename + ".txt", shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


def analyze_log(filename):
    print 'analyzing: ' + filename
    process_dict = {}
    inverted_process_dict = {}
    termination_list = []

    with open(dir_unpacked_path + filename + '.txt', 'r') as logfile:
        for line in logfile:
            # check if the line contains the system call for termination NtTerminateProcess
            if termination_instruction in line:
                termination_list.append(line.strip())
                print line
            # for each log line check if it the spawn of a new process
            words = line.split()
            if new_proc in words:
                # if it is save in the process dictionary the pid and process name
                pid = int(words[4].replace(',', ''))
                proc_name = words[5].replace(')', '')
                if pid in process_dict:
                    if proc_name in process_dict[pid]:
                        process_dict[pid][proc_name] += 1
                    else:
                        process_dict[pid][proc_name] = 1
                else:
                    process_dict[pid] = {}
                    process_dict[pid][proc_name] = 1
                # the same values will also be added to the inverted dictionary
                if proc_name in inverted_process_dict:
                    if pid in inverted_process_dict[proc_name]:
                        inverted_process_dict[proc_name][pid] += 1
                    else:
                        inverted_process_dict[proc_name][pid] = 1
                else:
                    inverted_process_dict[proc_name] = {}
                    inverted_process_dict[proc_name][pid] = 1

    sys.stdout = open(dir_analyzed_logs + filename + '_a.txt', 'w')
    pprint.pprint(process_dict)
    pprint.pprint(inverted_process_dict)
    pprint.pprint(termination_list)


def clean_log(filename):
    sys.stdout = sys.__stdout__
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')




def main():
    j = 0
    os.chdir(dir_panda_path)
    for filename in sorted(os.listdir(dir_pandalogs_path)):
        # each file has to be unpacked using the PANDA tool
        unpack_log(filename)
        analyze_log(filename)
        clean_log(filename)

        j += 1
        if j == 10:
            exit()


if __name__ == '__main__':
    main()
