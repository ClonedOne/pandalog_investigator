from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.utils import pi_strings
from pandaloginvestigator.core.domain.malware_object import Malware
import logging
import time
import traceback


dir_unpacked_path = None

context_switch = pi_strings.context_switch
instruction_termination = pi_strings.instruction_termination
instruction_process_creation = pi_strings.instruction_process_creation
instruction_write_memory = pi_strings.instruction_write_memory
instruction_read_memory = pi_strings.instruction_read_memory
instruction_sleep = pi_strings.instruction_sleep
instruction_raise_error = pi_strings.instruction_raise_error
error_manager = pi_strings.error_manager

file_corrupted_processes_dict = {}
db_file_malware_dict = {}
active_malware = None
logger = logging.getLogger(__name__)


def work(data_pack):
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path_p = data_pack[2]
    syscall_dict = data_pack[3]
    db_file_malware_name_map = data_pack[4]
    global active_malware, dir_unpacked_path, dir_analyzed_logs
    dir_unpacked_path = dir_unpacked_path_p
    j = 0.0
    t0 = time.time()
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId = ' + str(worker_id) + ' counting system calls on ' + str(total_files) + ' log files')
    for filename in filenames:
        active_malware = None
        if filename in db_file_malware_name_map:
            initialize_malware_object(filename, db_file_malware_name_map[filename], from_db=True)
            syscall_count(filename)
        else:
            print (worker_id, 'ERROR filename not in db')
        j += 1
        logger.info('System call counter' + str(worker_id) + ' ' + str((j * 100 / total_files)) + '%')
    total_time = time.time() - t0
    logger.info(str(worker_id) + ' Total time: ' + str(total_time))


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
# Checks if each line contains a the tag of a systems call. If so update frequency of that system call.
def syscall_count(filename):
    with open(dir_unpacked_path + '/' + filename, 'r', encoding='utf-8', errors='replace') as logfile:
        for line in logfile:
            try:
                if context_switch in line:
                    is_context_switch(filename, line, process_dict, inverted_process_dict)
                elif instruction_process_creation in line:
                    is_creating_process(line, filename)
                elif instruction_write_memory in line:
                    is_writing_memory(line, filename)
                elif instruction_sleep in line and active_malware:
                    is_calling_sleep()
                elif instruction_termination in line:
                    is_terminating(line, filename)
                elif instruction_read_memory in line and error_manager in line:
                    is_crashing(line, filename)
                elif instruction_raise_error in line and active_malware:
                    is_raising_error()
            except:
                traceback.print_exc()


# If a context switch happens this method is used to gather the information on which process is going in CPU.
# It gathers the process id and process name of the new process and the current value of the instruction counter.
# Then it tries to understand if the new process is a malware or a corrupted process.
def is_context_switch(filename, line):
    commas = line.strip().split(',')
    pid = int(commas[2].strip())
    proc_name = commas[3].split(')')[0].strip()
    current_instruction = int((commas[0].split()[0].split('='))[1])
    not_malware = False
    malware = is_db_malware(proc_name, filename)
    if not malware:
        malware = is_corrupted_process(proc_name, filename)
        if not malware:
            not_malware = True

    if not_malware and active_malware:
        deactivate_malware()
    elif malware and active_malware:
        deactivate_malware()
        is_malware(malware, pid, current_instruction)
    elif malware:
        is_malware(malware, pid, current_instruction)


# It is called only if the active_malware is not None.
# It finds the active malware, deactivates its active pid.
# Then it sets active_malware to None.
def deactivate_malware():
    global active_malware
    malware = active_malware
    if not malware:
        return -1
    active_pid = malware.get_active_pid()
    if active_pid == -1:
        return -1
    malware.deactivate_pid(active_pid)
    active_malware = None
    return 1


# This method is called if the process being context switched inside CPU is a malicious one.
# Checks if the current pid is not already in the pid list of the malware.
# If it isn't, it means it is the first instruction of the db_malware.
# Therefore it adds the new pid value to the malware's list.
# Then set active_malware to specified malware.
def is_malware(malware, pid, current_instruction):
    global active_malware
    pid_list = malware.get_pid_list()
    if pid not in pid_list:
        malware.add_pid(pid, Malware.FROM_DB)
    malware.set_active_pid(pid)
    active_malware = malware
