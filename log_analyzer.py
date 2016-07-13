import os
import utils
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

file_corrupted_processes_dict = {}
db_file_malware_dict = {}
is_active_malware = False
testing = False


# Checks if the process name is inside the db_file_malware_dict.
# This would mean that the current process is the original malware installed
# in the system. If found returns the malware.
def is_db_malware(proc_name, filename):
    if filename not in db_file_malware_dict:
        return None
    malware = db_file_malware_dict[filename]
    if malware.get_name() == proc_name:
        return malware
    else:
        return None


# Checks if the process name is inside the file_corrupted_processes_dict.
# If positive also checks if the current pid corresponds to a valid pid for that malware
# That is because spawned or memory written processes may have the same name of
# correct processes in the system. Therefore the method looks only for valid couples name/pid.
# If found returns the malware.
def is_corrupted_process(proc_name, pid, filename):
    if filename not in file_corrupted_processes_dict:
        return None
    malwares = file_corrupted_processes_dict[filename]
    for malware in malwares:
        if malware.get_name() == proc_name:
            return malware
    return None


# If the global variable is_active_malware is set to True, this method can be used to look for
# the malware which is currently active (before the context switch).
# If found returns the active malware.
def find_active_malware(filename):
    malware = db_file_malware_dict[filename]
    if malware.has_active_pid():
        return malware
    else:
        for malware in file_corrupted_processes_dict[filename]:
            if malware.has_active_pid():
                return malware
    return None


# If a context switch happens this method is used to gather the information on which process is going in CPU.
# It gathers the process id and process name of the new process and the current value of the instruction counter.
# First it updates the related dictionaries with the new information.
# Then it tries to understand if the new process is a malware or a corrupted process.
# If it is a correct process and the previous process was a malware, update that malware instruction count.
# If it is a malware/corrupt process, update the instruction count of a previous malicious process
# (if there was one) and call the method is_malware().
def is_context_switch(filename, words, process_dict, inverted_process_dict):
    pid = int(words[4].replace(',', ''))
    proc_name = words[5].replace(')', '')
    current_instruction = int((words[0].split('='))[1])
    not_malware = False
    utils.update_dictionaries(pid, process_dict, proc_name, inverted_process_dict)

    malware = is_db_malware(proc_name, filename)
    if not malware:
        malware = is_corrupted_process(proc_name, pid, filename)
        if not malware:
            not_malware = True

    if not_malware and is_active_malware:
        if testing:
            print 'first' + ' at instruction ' + str(current_instruction)
        update_malware_instruction_count(filename, current_instruction)
    elif malware and is_active_malware:
        if testing:
            print 'second' + ' at instruction ' + str(current_instruction)
        update_malware_instruction_count(filename, current_instruction)
        is_malware(malware, pid, current_instruction)
    elif malware:
        if testing:
            print 'third' + ' at instruction ' + str(current_instruction)
        is_malware(malware, pid, current_instruction)


# Updates the instruction count of a malicious process once it is context switched out of the CPU.
# It is called only if the is_active_malware is set to True.
# It finds the active malware, updates its instruction count and deactivates its active pid.
# Then it sets is_active_malware to False.
def update_malware_instruction_count(filename, current_instruction):
    global is_active_malware
    malware = find_active_malware(filename)
    if not malware:
        return -1
    active_pid = malware.get_active_pid()
    if active_pid == -1:
        return -1
    malware_starting_instruction = malware.get_starting_instruction(active_pid)
    instruction_delta = current_instruction - malware_starting_instruction
    malware.add_instruction_executed(active_pid, instruction_delta)
    malware.deactivate_pid(active_pid)
    is_active_malware = False
    if testing:
        print 'process ' + malware.get_name() + ' ' + str(active_pid) + ' increased by ' + str(instruction_delta) +\
          ' at instruction ' + str(current_instruction)
    return 1


# Handles termination system calls.
# Analyze the log to find out process name and id of the terminating and terminated processes.
# Checks if terminating process is a malware and if so updates malware's termination information.
def is_terminating(words, filename):
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

    malware = is_db_malware(terminating_name, filename)
    if not malware:
        malware = is_corrupted_process(terminating_name, terminating_pid, filename)
    if malware and malware.is_valid_pid(terminating_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == terminating_pid:
        if testing:
            print 'process ' + terminating_name + ' ' + str(terminating_pid) + ' is terminating ' +\
              terminated_name + ' ' + str(terminated_pid) + ' at instruction ' + str(current_instruction)
        active_pid = malware.get_active_pid()
        malware.add_terminated_process(active_pid, terminated_pid, terminated_name, current_instruction)


# Handles process creation system calls.
# Analyze the log to find out process name and id of the creating and created processes.
# Checks if the creating process is a malware and if so updates the malware's creation information.
# If the creating process is a malicious one, the created process will also be considered as corrupted.
# If the new malware is already known adds the created pid to that object after having checked
# that the created pid is not already a valid pid for that malicious process.
# Else create a new malware object and initialize it with the created pid.
# The path for the executable of the created process is gathered through the method get_new_path().
def is_creating_process(words, filename):
    current_instruction = int((words[0].split('='))[1])
    new_path = utils.get_new_path(words)
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

    malware = is_db_malware(creating_name, filename)
    if not malware:
        malware = is_corrupted_process(creating_name, creating_pid, filename)

    if malware and malware.is_valid_pid(creating_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == creating_pid:
        if testing:
            print 'process ' + creating_name + ' ' + str(creating_pid) + ' is creating ' + \
              created_name + ' ' + str(created_pid) + ' at instruction ' + str(current_instruction)
        active_pid = malware.get_active_pid()
        malware.add_spawned_process(active_pid, created_pid, created_name, current_instruction, new_path)
        target = is_db_malware(created_name, filename)
        if not target:
            target = is_corrupted_process(created_name, created_pid, filename)
        if target:
            if not target.is_valid_pid(created_pid):
                target.add_pid(created_pid)
            return
        new_malware = initialize_malware_object(filename, created_name)
        new_malware.add_pid(created_pid)


# Handles the write on virtual memory system calls.
# Analyze the log to find out process name and id of the writing and written processes.
# Checks if the writing process is a malware and if so updates the malware memory writing information.
# If the writing process is a malicious one, the written process will also be considered as corrupted.
# If the new malware is already known adds the written pid to that object after having checked
# that the written pid is not already a valid pid for that malicious process.
# Else create a new malware object and initialize it with the written pid.
def is_writing_memory(words, filename):
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

    malware = is_db_malware(writing_name, filename)
    if not malware:
        malware = is_corrupted_process(writing_name, writing_pid, filename)

    if malware and malware.is_valid_pid(writing_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == writing_pid:
        if testing:
            print 'process ' + writing_name + ' ' + str(writing_pid) + ' is writing on ' + \
              written_name + ' ' + str(written_pid) + ' at instruction ' + str(current_instruction)
        active_pid = malware.get_active_pid()
        malware.add_written_memory(active_pid, written_pid, written_name, current_instruction)
        target = is_db_malware(written_name, filename)
        if not target:
            if testing:
                print 'process ' + written_name + ' ' + str(written_pid) + ' is not a db malware'
            target = is_corrupted_process(written_name, written_pid, filename)
        if target:
            if not target.is_valid_pid(written_pid):
                target.add_pid(written_pid)
            return
        if testing:
            print 'process ' + written_name + ' ' + str(written_pid) + ' is not even a corrupted process'
        new_malware = initialize_malware_object(filename, written_name)
        new_malware.add_pid(written_pid)


# This method is called if the process being context switched inside CPU is a malicious one.
# Checks if the current pid is not already in the pid list of the malware.
# If it isn't, it means it is the first instruction of the db_malware.
# Therefore it adds the new pid value to the malware's list.
# Then it updates malware's starting instruction for that pid and set is_active_malware to True.
def is_malware(malware, pid, current_instruction):
    global is_active_malware
    pid_list = malware.get_pid_list()
    if pid not in pid_list:
        malware.add_pid(pid)
    malware.update_starting_instruction(pid, current_instruction)
    malware.set_active_pid(pid)
    is_active_malware = True


# Utility method to initialize a new malware object given the relative process name and file name.
# Checks whether the new process would be the db_malware or a corrupted process.
def initialize_malware_object(filename, malware_name, from_db=False):
    malware = Malware(malware_name)
    if from_db:
        db_file_malware_dict[filename] = malware
        return malware
    if filename in file_corrupted_processes_dict:
        file_corrupted_processes_dict[filename].append(malware)
    else:
        file_corrupted_processes_dict[filename] = []
        file_corrupted_processes_dict[filename].append(malware)
    return malware


# Analyze the log file line by line.
# Checks if each line contains a context switch, a process creation, a memory write or a process termination.
# At the end print a summary of the analyzed mawlares on a file.
def analyze_log(filename):
    print 'analyzing: ' + filename
    process_dict = {}
    inverted_process_dict = {}

    with open(dir_unpacked_path + filename + '.txz.plog.txt', 'r') as logfile:
        for line in logfile:
            line = line.strip()
            words = line.split()
            # check if line contains the system call for termination of processes
            if instruction_termination in line:
                is_terminating(words, filename)
            # check if the line contains the system call for creation of new processes
            elif instruction_process_creation in line:
                is_creating_process(words, filename)
            # check if malware is writing the virtual memory of another process
            elif instruction_write_memory in line:
                is_writing_memory(words, filename)
            # check if line logs a context switch
            elif context_switch in line:
                is_context_switch(filename, words, process_dict, inverted_process_dict)

    utils.output_on_file(filename, process_dict, inverted_process_dict, dir_analyzed_logs,
                         db_file_malware_dict, file_corrupted_processes_dict)


# For testing purposes
def single_test(db_file_malware_name_map):
    filename = '4fc89505-75a0-4734-ac6d-1ebbdca28caa.txz.plog'
    if filename[:-9] in db_file_malware_name_map:
        initialize_malware_object(filename[:-9], db_file_malware_name_map[filename[:-9]], from_db=True)
    analyze_log(filename[:-9])


# Each file has to be unpacked using the PANDA tool
# Analyze each unpacked log file calling analyze_log()
# Since the size of the unpacked logs may engulf the disk, delete the file after the process
def main():
    os.chdir(dir_panda_path)
    db_file_malware_name_map = db_manager.acquire_malware_file_dict()
    filenames = sorted(os.listdir(dir_pandalogs_path))
    if testing:
        single_test(db_file_malware_name_map)
        return
    # j = 0
    for filename in filenames:
        global is_active_malware
        is_active_malware = False
        utils.unpack_log(filename, unpack_command, dir_pandalogs_path, dir_unpacked_path)
        if filename[:-9] in db_file_malware_name_map:
            initialize_malware_object(filename[:-9], db_file_malware_name_map[filename[:-9]], from_db=True)
            analyze_log(filename[:-9])
        else:
            print 'ERROR filename not in db'

        utils.clean_log(filename, dir_unpacked_path)
        # j += 1
        # if j == 5:
        #     break
    utils.final_output(dir_project_path, filenames, db_file_malware_dict, file_corrupted_processes_dict)


if __name__ == '__main__':
    main()
