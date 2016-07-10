import os
import subprocess
import pprint
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
instruction_process_creation = 'nt_create_user_process'
instruction_write_memory = 'nt_write_virtual_memory'

malware_dict = {}
active_malware = False


def get_new_path(words):
    line = ''
    fixed = 'name=['
    for word in words:
        line += word + ' '
    index = line.find(fixed)
    line = line[index:]
    return os.path.normpath(line.split('[')[1].replace(']', ''))


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
    if terminating_name == malware.get_name() and malware.is_valid_pid(terminating_pid) \
            and malware.get_active_pid() == terminating_pid:
        active_pid = malware.get_active_pid()
        malware.add_terminated_process(active_pid, terminated_pid, terminated_name, current_instruction)


def is_creating_process(malware, words):
    current_instruction = int((words[0].split('='))[1])
    new_path = get_new_path(words)
    creating_pid = 0
    creating_name = ''
    created_pid = 0
    created_name = ''
    for i in range(len(words)):
        if words[i] == 'cur,':
            creating_pid = int(words[i + 1].strip().replace(',', ''))
            creating_name = words[i + 2].strip().replace(')', '')
        elif words[i] == 'new,':
            created_pid = int(words[i + 1].strip().replace(',', ''))
            created_name = words[i + 2].strip().replace(')', '')
    if creating_name == malware.get_name() and malware.is_valid_pid(creating_pid) \
            and malware.get_active_pid() == creating_pid:
        active_pid = malware.get_active_pid()
        malware.add_spawned_process(active_pid, created_pid, created_name, current_instruction, new_path)


def is_writing_memory(malware, words):
    current_instruction = int((words[0].split('='))[1])
    writing_pid = 0
    writing_name = ''
    written_pid = 0
    written_name = ''
    for i in range(len(words)):
        if words[i] == 'proc,':
            writing_pid = int(words[i + 1].strip().replace(',', ''))
            # compensate for problem in formatting of log
            writing_name = (words[i + 2].strip().replace(')', '')).split('(')[0]
        elif words[i] == 'target,':
            written_pid = int(words[i + 1].strip().replace(',', ''))
            written_name = words[i + 2].strip().replace(')', '')
    if writing_name == malware.get_name() and malware.is_valid_pid(writing_pid) \
            and malware.get_active_pid() == writing_pid:
        active_pid = malware.get_active_pid()
        malware.add_written_memory(active_pid, written_pid, written_name, current_instruction)


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


def initialize_malware_object(filename, malware_name):
    malware_dict[filename] = Malware(malware_name)


def unpack_log(filename):
    print 'unpacking: ' + filename
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + filename + ".txt", shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


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
            # check if the line contains the system call for creation of new processes
            elif instruction_process_creation in line:
                is_creating_process(malware, words)
            # check if malware is writing the virtual memory of another process
            elif instruction_write_memory in line:
                is_writing_memory(malware, words)
            # for each log line check if it logs a context switch
            elif context_switch in words:
                is_context_switch(words, filename, malware, process_dict, inverted_process_dict)

    output_on_file(filename, process_dict, inverted_process_dict, malware)


def clean_log(filename):
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')


def final_output():
    res_file = open(dir_project_path + 'resfile.txt', 'w')
    for entry in malware_dict:
        res_file.write('File name: ' + entry + '\n\n')
        res_file.write(str(malware_dict[entry]) + '\n\n\n')


def output_on_file(filename, process_dict, inverted_process_dict, malware):
    outfile = open(dir_analyzed_logs + filename + '_a.txt', 'w')
    pprint.pprint(process_dict, outfile)
    outfile.write('\n')
    pprint.pprint(inverted_process_dict, outfile)
    outfile.write('\n')
    outfile.write(str(malware))


def main():
    os.chdir(dir_panda_path)
    big_file_malware_dict = db_manager.acquire_malware_file_dict()
    j = 0
    for filename in sorted(os.listdir(dir_pandalogs_path)):
        global active_malware
        active_malware = False
        # each file has to be unpacked using the PANDA tool
        unpack_log(filename)
        # analyze the unpacked log file
        if filename[:-9] in big_file_malware_dict:
            initialize_malware_object(filename[:-9], big_file_malware_dict[filename[:-9]])
            analyze_log(filename, malware_dict[filename[:-9]])
        else:
            print 'ERROR filename not in db'
        # since the size of the unpacked logs may engulf the disk, delete the file after the process
        # clean_log(filename)
        j += 1
        if j == 5:
            break
    final_output()

    '''  # FOR TESTING PURPOSES
    filename = '4fc89505-75a0-4734-ac6d-1ebbdca28caa.txz.plog'
    if filename[:-9] in big_file_malware_dict:
        initialize_malware_object(filename[:-9], big_file_malware_dict[filename[:-9]])
    analyze_log(filename, malware_dict[filename[:-9]])
    '''


if __name__ == '__main__':
    main()
