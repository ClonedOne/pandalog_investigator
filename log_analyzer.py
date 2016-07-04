import os
import subprocess
import pprint
import sys
import db_manager
from malware_object import Malware

dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'
dir_malware_db = '/home/yogaub/projects/seminar/database'

unpack_command = './pandalog_reader'
new_proc = 'new_pid,'
termination_instruction = 'num=369)'
termination_dict = {}
malware_dict = {}
active_malware = False


def unpack_log(filename):
    print 'unpacking: ' + filename
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + filename + ".txt", shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


def is_malware(filename, pid, current_instruction):
    malware = malware_dict[filename]
    pid_list = malware.get_pid_list()

    # check if the current pid is already in the pid list of the malware
    if pid in pid_list:
        position = malware.get_pid_position(pid)
    else:
        malware.add_pid(pid)
        position = malware.get_pid_position(pid)

    # once the current malware has been identified, update its current instruction value
    malware.update_starting_instruction(position, current_instruction)
    malware.set_active_pid(position)
    global active_malware
    active_malware = True
    return 1


def update_malware_instruction_count(filename, current_instruction):
    malware = malware_dict[filename]
    position = malware.get_active_pid()
    if position == -1:
        return -1
    malware_starting_instruction = malware.get_starting_instruction(position)
    instruction_delta = current_instruction - malware_starting_instruction
    malware.add_instruction_executed(position, instruction_delta)
    malware.deactivate_pid(position)
    global active_malware
    active_malware = False
    return 1


def analyze_log(filename, malware_name):
    print 'analyzing: ' + filename
    process_dict = {}
    inverted_process_dict = {}
    termination_list = []

    with open(dir_unpacked_path + filename + '.txt', 'r') as logfile:
        for line in logfile:
            # check if the line contains the system call for termination NtTerminateProcess
            if termination_instruction in line:
                termination_list.append(line.strip())
            words = line.split()

            # for each log line check if it logs a context switch
            if new_proc in words:
                pid = int(words[4].replace(',', ''))
                proc_name = words[5].replace(')', '')
                current_instruction = int((words[0].split('='))[1])

                # check if the process name is in the known malware list
                if proc_name == malware_name:
                    is_malware(filename[:-9], pid, current_instruction)
                elif active_malware:
                    res = update_malware_instruction_count(filename[:-9], current_instruction)
                    if res == -1:
                        print line

                # since it is a context switch save in the process dictionary the pid and process name
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
    pprint.pprint(malware_dict[filename[:-9]])
    sys.stdout = sys.__stdout__


def clean_log(filename):
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')


def initialize_malware_object(filename, malware_name):
    new_malware = Malware(malware_name)
    malware_dict[filename] = new_malware


def main():
    j = 0
    os.chdir(dir_panda_path)
    big_file_malware_dict = db_manager.acquire_malware_file_dict()
    for filename in sorted(os.listdir(dir_pandalogs_path)):
        global active_malware
        active_malware = False
        # each file has to be unpacked using the PANDA tool
        unpack_log(filename)
        # analyze the unpacked log file
        if filename[:-9] in big_file_malware_dict:
            initialize_malware_object(filename[:-9], big_file_malware_dict[filename[:-9]])
            #print malware_dict
            analyze_log(filename, big_file_malware_dict[filename[:-9]])
        else:
            print 'ERROR filename not in db'
        # since the size of the unpacked logs will engulf the disk, delete the file after the process
        clean_log(filename)

        j += 1
        if j == 10:
            exit()


if __name__ == '__main__':
    main()
