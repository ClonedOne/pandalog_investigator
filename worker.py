import utils
import os
import traceback
import time
from malware_object import Malware

dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'

unpack_command = './pandalog_reader'
context_switch = u'new_pid,'
instruction_termination = u'nt_terminate_process'
instruction_process_creation = u'nt_create_user_process'
instruction_write_memory = u'nt_write_virtual_memory'
instruction_sleep = u'(num=98)'

file_corrupted_processes_dict = {}
db_file_malware_dict = {}
file_terminate_dict = {}
file_sleep_dict = {}
active_malware = None


# Checks if the malware_objects associated with the filename have called the sleep function on all their pids.
def is_sleeping_all(filename):
    all_pids = set()
    all_sleep = set()
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        pid_list = malware.get_pid_list()
        for pid in pid_list:
            all_pids.add((malware.get_name(), pid))
            sleep_count = malware.get_sleep(pid)
            if sleep_count:
                all_sleep.add((malware.get_name(), pid))

    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                all_pids.add((malware.get_name(), pid))
                sleep_count = malware.get_sleep(pid)
                if sleep_count:
                    all_sleep.add((malware.get_name(), pid))

    not_empty = len(all_pids) > 0
    if all_pids.issubset(all_sleep) and not_empty:
        file_sleep_dict[filename] = True
        return True
    else:
        file_sleep_dict[filename] = False
        return False


# Checks if the malware_objects associated with the filename have terminated all their pids.
def is_terminating_all(filename):
    all_pids = set()
    all_term = set()
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        pid_list = malware.get_pid_list()
        for pid in pid_list:
            all_pids.add((malware.get_name(), pid))
            terms = malware.get_terminated_processes(pid)
            for term in terms:
                all_term.add((term[1], term[0]))

    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                all_pids.add((malware.get_name(), pid))
                terms = malware.get_terminated_processes(pid)
                for term in terms:
                    all_term.add((term[1], term[0]))

    not_empty = len(all_pids) > 0
    if all_pids.issubset(all_term) and not_empty:
        file_terminate_dict[filename] = True
        return True
    else:
        file_terminate_dict[filename] = False
        return False


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
def is_corrupted_process(proc_name, filename):
    if filename not in file_corrupted_processes_dict:
        return None
    malwares = file_corrupted_processes_dict[filename]
    for malware in malwares:
        if malware.get_name() == proc_name:
            return malware
    return None


# If a context switch happens this method is used to gather the information on which process is going in CPU.
# It gathers the process id and process name of the new process and the current value of the instruction counter.
# First it updates the related dictionaries with the new information.
# Then it tries to understand if the new process is a malware or a corrupted process.
# If it is a correct process and the previous process was a malware, update that malware instruction count.
# If it is a malware/corrupt process, update the instruction count of a previous malicious process
# (if there was one) and call the method is_malware().
def is_context_switch(filename, line, process_dict, inverted_process_dict):
    commas = line.strip().split(',')
    pid = int(commas[2].strip())
    proc_name = commas[3].split(')')[0].strip()
    current_instruction = int((commas[0].split()[0].split('='))[1])
    not_malware = False
    utils.update_dictionaries(pid, process_dict, proc_name, inverted_process_dict)

    malware = is_db_malware(proc_name, filename)
    if not malware:
        malware = is_corrupted_process(proc_name, filename)
        if not malware:
            not_malware = True

    if not_malware and active_malware:
        update_malware_instruction_count(current_instruction)
    elif malware and active_malware:
        update_malware_instruction_count(current_instruction)
        is_malware(malware, pid, current_instruction)
    elif malware:
        is_malware(malware, pid, current_instruction)


# Updates the instruction count of a malicious process once it is context switched out of the CPU.
# It is called only if the active_malware is not None.
# It finds the active malware, updates its instruction count and deactivates its active pid.
# Then it sets active_malware to None.
def update_malware_instruction_count(current_instruction):
    global active_malware
    malware = active_malware
    if not malware:
        return -1
    active_pid = malware.get_active_pid()
    if active_pid == -1:
        return -1
    malware_starting_instruction = malware.get_starting_instruction(active_pid)
    instruction_delta = current_instruction - malware_starting_instruction
    malware.add_instruction_executed(active_pid, instruction_delta)
    malware.deactivate_pid(active_pid)
    active_malware = None
    return 1


# Handles termination system calls.
# Analyze the log to find out process name and id of the terminating and terminated processes.
# Checks if terminating process is a malware and if so updates malware's termination information.
def is_terminating(line, filename):
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    terminating_pid = int(commas[2].strip())
    terminating_name = commas[3].split(')')[0].strip()
    terminated_pid = int(commas[5].strip())
    terminated_name = commas[6].split(')')[0].strip()

    malware = is_db_malware(terminating_name, filename)
    if not malware:
        malware = is_corrupted_process(terminating_name, filename)
    if malware and malware.is_valid_pid(terminating_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == terminating_pid:
        active_pid = malware.get_active_pid()
        malware.add_terminated_process(active_pid, terminated_pid, terminated_name, current_instruction)


# Handles NtDelayExecution system calls.
# The purpose is to understand if the malicious process is trying to hide itself by calling the sleep function
# for enough time to avoid examination.
def is_calling_sleep():
    global active_malware
    if active_malware:
        malware = active_malware
        if malware:
            active_pid = malware.get_active_pid()
            malware.add_sleep(active_pid)


# Handles process creation system calls.
# Analyze the log to find out process name and id of the creating and created processes.
# Checks if the creating process is a malware and if so updates the malware's creation information.
# If the creating process is a malicious one, the created process will also be considered as corrupted.
# If the new malware is already known adds the created pid to that object after having checked
# that the created pid is not already a valid pid for that malicious process.
# Else create a new malware object and initialize it with the created pid.
# The path for the executable of the created process is gathered through the method get_new_path().
def is_creating_process(line, filename):
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    new_path = utils.get_new_path(line)
    creating_pid = int(commas[2].strip())
    creating_name = commas[3].split(')')[0].strip()
    created_pid = int(commas[5].strip())
    created_name = commas[6].split(')')[0].strip()

    malware = is_db_malware(creating_name, filename)
    if not malware:
        malware = is_corrupted_process(creating_name, filename)

    if malware and malware.is_valid_pid(creating_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == creating_pid:
        active_pid = malware.get_active_pid()
        malware.add_spawned_process(active_pid, created_pid, created_name, current_instruction, new_path)
        target = is_db_malware(created_name, filename)
        if not target:
            target = is_corrupted_process(created_name, filename)
        if target:
            if not target.is_valid_pid(created_pid):
                target.add_pid(created_pid, Malware.CREATED)
            return
        new_malware = initialize_malware_object(filename, created_name)
        new_malware.add_pid(created_pid, Malware.CREATED)


# Handles the write on virtual memory system calls.
# Analyze the log to find out process name and id of the writing and written processes.
# Checks if the writing process is a malware and if so updates the malware memory writing information.
# If the writing process is a malicious one, the written process will also be considered as corrupted.
# If the new malware is already known adds the written pid to that object after having checked
# that the written pid is not already a valid pid for that malicious process.
# Else create a new malware object and initialize it with the written pid.
def is_writing_memory(line, filename):
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    writing_pid = int(commas[2].strip())
    writing_name = commas[3].split(')')[0].strip()
    written_pid = int(commas[5].strip())
    written_name = commas[6].split(')')[0].strip()

    malware = is_db_malware(writing_name, filename)
    if not malware:
        malware = is_corrupted_process(writing_name, filename)

    if malware and malware.is_valid_pid(writing_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == writing_pid:
        active_pid = malware.get_active_pid()
        malware.add_written_memory(active_pid, written_pid, written_name, current_instruction)
        target = is_db_malware(written_name, filename)
        if not target:
            target = is_corrupted_process(written_name, filename)
        if target:
            if not target.is_valid_pid(written_pid):
                target.add_pid(written_pid, Malware.WRITTEN)
            return
        new_malware = initialize_malware_object(filename, written_name)
        new_malware.add_pid(written_pid, Malware.WRITTEN)


# This method is called if the process being context switched inside CPU is a malicious one.
# Checks if the current pid is not already in the pid list of the malware.
# If it isn't, it means it is the first instruction of the db_malware.
# Therefore it adds the new pid value to the malware's list.
# Then it updates malware's starting instruction for that pid and set active_malware to specified malware.
def is_malware(malware, pid, current_instruction):
    global active_malware
    pid_list = malware.get_pid_list()
    if pid not in pid_list:
        malware.add_pid(pid, Malware.FROM_DB)
    malware.update_starting_instruction(pid, current_instruction)
    malware.set_active_pid(pid)
    active_malware = malware


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
    process_dict = {}
    inverted_process_dict = {}

    # with codecs.open(dir_unpacked_path + filename + '.txz.plog.txt', 'r', encoding='utf-8') as logfile:
    with open(dir_unpacked_path + filename + '.txz.plog.txt', 'r') as logfile:
    # with io.open(dir_unpacked_path + filename + '.txz.plog.txt', encoding='utf-8', errors='replace') as logfile:
        for line in logfile:
            line = unicode(line, errors='ignore')
            if context_switch in line:
                try:
                    is_context_switch(filename, line, process_dict, inverted_process_dict)
                except:
                    traceback.print_exc()
            elif instruction_process_creation in line:
                try:
                    is_creating_process(line, filename)
                except:
                    traceback.print_exc()
            elif instruction_write_memory in line:
                try:
                    is_writing_memory(line, filename)
                except:
                    traceback.print_exc()
            elif instruction_sleep in line and active_malware:
                try:
                    is_calling_sleep()
                except:
                    traceback.print_exc()
            elif instruction_termination in line:
                try:
                    is_terminating(line, filename)
                except:
                    traceback.print_exc()

    terminating_all = is_terminating_all(filename)
    sleeping_all = is_sleeping_all(filename)
    t1 = time.time()
    utils.output_on_file(filename, process_dict, inverted_process_dict, dir_analyzed_logs,
                         db_file_malware_dict, file_corrupted_processes_dict, terminating_all, sleeping_all)
    return time.time() - t1


def work((worker_id, filenames, db_file_malware_name_map)):
    global active_malware
    j = 0.0
    t0 = time.time()
    unpack_time = 0.0
    clean_time = 0.0
    outfile_time = 0.0
    total_files = float(len(filenames))
    os.chdir(dir_panda_path)
    for filename in filenames:
        reduced_filename = filename[:-9]
        # if filename == '14127b04-dd53-4295-9efc-6ed48eb3a79d.txz.plog.txt':
        #     continue
        active_malware = None
        t1 = time.time()
        utils.unpack_log(filename, unpack_command, dir_pandalogs_path, dir_unpacked_path)
        unpack_time += time.time() - t1
        if reduced_filename in db_file_malware_name_map:
            initialize_malware_object(reduced_filename, db_file_malware_name_map[reduced_filename], from_db=True)
            outfile_time += analyze_log(reduced_filename)
        else:
            print worker_id, 'ERROR filename not in db'
        t1 = time.time()
        utils.clean_log(filename, dir_unpacked_path)
        clean_time += time.time() - t1
        j += 1
        print worker_id, ((j * 100) / total_files)
        # if j == 100:
        #     break
    total_time = time.time() - t0
    print worker_id, 'Total unpack time', unpack_time
    print worker_id, 'Total clean time', clean_time
    print worker_id, 'Total outfile time', outfile_time
    print worker_id, 'Total time', total_time
    return db_file_malware_dict, file_corrupted_processes_dict, file_terminate_dict, file_sleep_dict