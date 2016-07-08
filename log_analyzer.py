import os
import subprocess
import pprint
import sys
import db_manager
from malware_object import Malware

dir_project_path = '/home/yogaub/projects/seminar/'
dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'
dir_malware_db = '/home/yogaub/projects/seminar/database'

unpack_command = './pandalog_reader'
context_switch = 'new_pid,'
instruction_termination = 'nt_terminate_process'
instruction_process_Creation = 'nt_create_user_process'

malware_dict = {}
termination_dict = {}

active_malware = False


def update_dictionaries(pid, process_dict, proc_name, inverted_process_dict):
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


def is_context_switch(words, filename, malware, process_dict, inverted_process_dict):
    pid = int(words[4].replace(',', ''))
    proc_name = words[5].replace(')', '')
    current_instruction = int((words[0].split('='))[1])
    # check if the process name is in the known malware list
    if proc_name == malware.get_name() and active_malware:
        update_malware_instruction_count(filename[:-9], current_instruction)
        is_malware(filename[:-9], pid, current_instruction)
    elif proc_name == malware.get_name():
        is_malware(filename[:-9], pid, current_instruction)
    elif active_malware:
        update_malware_instruction_count(filename[:-9], current_instruction)

    # since it is a context switch save in the process dictionary the pid and process name
    update_dictionaries(pid, process_dict, proc_name, inverted_process_dict)


def is_terminating(malware, words):
    current_instruction = int((words[0].split('='))[1])
    terminating_pid = 0
    terminating_name = ''
    terminated_pid = 0
    terminated_name = ''
    for i in range(len(words)):
        if words[i] == 'cur,':
            terminating_pid = int(words[i+1].strip().replace(',', ''))
            terminating_name = words[i+2].strip().replace(')', '')
        elif words[i] == 'term,':
            terminated_pid = int(words[i+1].strip().replace(',', ''))
            terminated_name = words[i+2].strip().replace(')', '')
    if terminating_name == malware.get_name() and malware.is_valid_pid(terminating_pid):
        active_pid = malware.get_active_pid()
        malware.add_terminated_process(active_pid, terminated_pid, terminated_name, current_instruction)


def unpack_log(filename):
    print 'unpacking: ' + filename
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + filename + ".txt", shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


def is_malware(filename, pid, current_instruction):
    malware = malware_dict[filename]
    pid_list = malware.get_pid_list()

    # check if the current pid is not already in the pid list of the malware
    if pid not in pid_list:
        malware.add_pid(pid)

    # once the current malware has been identified, update its current instruction value
    malware.update_starting_instruction(pid, current_instruction)
    malware.set_active_pid(pid)
    global active_malware
    active_malware = True
    return 1


def update_malware_instruction_count(filename, current_instruction):
    malware = malware_dict[filename]
    active_pid = malware.get_active_pid()
    if active_pid == -1:
        return -1
    malware_starting_instruction = malware.get_starting_instruction(active_pid)
    instruction_delta = current_instruction - malware_starting_instruction
    malware.add_instruction_executed(active_pid, instruction_delta)
    malware.deactivate_pid(active_pid)
    global active_malware
    active_malware = False
    return 1


def analyze_log(filename, malware):
    print 'analyzing: ' + filename
    process_dict = {}
    inverted_process_dict = {}

    with open(dir_unpacked_path + filename + '.txt', 'r') as logfile:
        for line in logfile:
            if not line.strip(): break
            line = line.strip()
            words = line.split()

            # check if the line contains the system call for termination NtTerminateProcess
            if instruction_termination in line:
                is_terminating(malware, words)
                continue

            # for each log line check if it logs a context switch
            if context_switch in words:
                is_context_switch(words, filename, malware, process_dict, inverted_process_dict)

    outfile = open(dir_analyzed_logs + filename + '_a.txt', 'w')
    pprint.pprint(process_dict, outfile)
    pprint.pprint(inverted_process_dict, outfile)
    for pid in malware.get_pid_list():
        pprint.pprint(malware.get_terminated_processes(pid), outfile)
    pprint.pprint(malware_dict[filename[:-9]], outfile)


def clean_log(filename):
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')


def initialize_malware_object(filename, malware_name):
    malware_dict[filename] = Malware(malware_name)


def main():
    os.chdir(dir_panda_path)
    big_file_malware_dict = db_manager.acquire_malware_file_dict()
    '''
    j = 0
    for filename in sorted(os.listdir(dir_pandalogs_path)):
        global active_malware
        active_malware = False
        # each file has to be unpacked using the PANDA tool
        unpack_log(filename)
        # analyze the unpacked log file
        if filename[:-9] in big_file_malware_dict:
            initialize_malware_object(filename[:-9], big_file_malware_dict[filename[:-9]])
            #print malware_dict
            analyze_log(filename, malware_dict[filename[:-9]])
        else:
            print 'ERROR filename not in db'
        # since the size of the unpacked logs will engulf the disk, delete the file after the process
        clean_log(filename)
        j += 1
        if j == 10:
            break

    res_file =  open(dir_project_path + 'resfile.txt', 'w')
    for entry in malware_dict:
        res_file.write(entry + '\n')
        res_file.write(str(malware_dict[entry]) + '\n')

    for entry in termination_dict:
        res_file.write(entry + '\n')
        res_file.write(str(termination_dict[entry]) + '\n')

    '''  # FOR TESTING PURPOSES
    filename = '4fc89505-75a0-4734-ac6d-1ebbdca28caa.txz.plog'
    if filename[:-9] in big_file_malware_dict:
        initialize_malware_object(filename[:-9], big_file_malware_dict[filename[:-9]])
    analyze_log(filename, malware_dict[filename[:-9]])


if __name__ == '__main__':
    main()
