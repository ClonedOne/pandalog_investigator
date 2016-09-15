from pandaloginvestigator.core.utils import domain_utils
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
system_call_tag = pi_strings.system_call_tag

file_corrupted_processes_dict = {}
db_file_malware_dict = {}
active_malware = None
logger = logging.getLogger(__name__)


def work(data_pack):
    t0 = time.time()
    j = 0.0
    filename_syscall_dict = {}
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path_p = data_pack[2]
    syscall_dict = data_pack[3]
    db_file_malware_name_map = data_pack[4]
    global active_malware, dir_unpacked_path, dir_analyzed_logs
    dir_unpacked_path = dir_unpacked_path_p
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId = ' + str(worker_id) + ' counting system calls on ' + str(total_files) + ' log files')
    for filename in filenames:
        active_malware = None
        if filename in db_file_malware_name_map:
            domain_utils.initialize_malware_object(filename, db_file_malware_name_map[filename], from_db=True)
            filename_syscall_dict[filename] = syscall_count(filename)
        else:
            print (worker_id, 'ERROR filename not in db')
        j += 1
        logger.info('System call counter' + str(worker_id) + ' ' + str((j * 100 / total_files)) + '%')
    total_time = time.time() - t0
    logger.info(str(worker_id) + ' Total time: ' + str(total_time))


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
                elif system_call_tag in line and active_malware:

            except:
                traceback.print_exc()


# If a context switch happens this method is used to gather the information on which process is going in CPU.
# It gathers the process id and process name of the new process and the current value of the instruction counter.
# Then it tries to understand if the new process is a malware or a corrupted process.
def is_context_switch(filename, line):
    commas = line.strip().split(',')
    pid = int(commas[2].strip())
    proc_name = commas[3].split(')')[0].strip()
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
        is_malware(malware, pid)
    elif malware:
        is_malware(malware, pid)


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
def is_malware(malware, pid):
    global active_malware
    pid_list = malware.get_pid_list()
    if pid not in pid_list:
        malware.add_pid(pid, Malware.FROM_DB)
    malware.set_active_pid(pid)
    active_malware = malware


# Handles the write on virtual memory system calls.
# Analyze the log to find out process name and id of the writing and written processes.
# Checks if the writing process is a malware.
# If the writing process is a malicious one, the written process will also be considered as corrupted.
# If the new malware is already known adds the written pid to that object after having checked
# that the written pid is not already a valid pid for that malicious process.
# Else create a new malware object and initialize it with the written pid.
def is_writing_memory(line, filename):
    commas = line.strip().split(',')
    writing_pid = int(commas[2].strip())
    writing_name = commas[3].split(')')[0].strip()
    written_pid = int(commas[5].strip())
    written_name = commas[6].split(')')[0].strip()

    malware = is_db_malware(writing_name, filename)
    if not malware:
        malware = is_corrupted_process(writing_name, filename)

    if malware and malware.is_valid_pid(writing_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == writing_pid:
        target = is_db_malware(written_name, filename)
        if not target:
            target = is_corrupted_process(written_name, filename)
        if target:
            if not target.is_valid_pid(written_pid):
                target.add_pid(written_pid, Malware.WRITTEN)
            return
        new_malware = domain_utils.initialize_malware_object(filename, written_name, db_file_malware_dict, file_corrupted_processes_dict)
        new_malware.add_pid(written_pid, Malware.WRITTEN)


# Handles process creation system calls.
# Analyze the log to find out process name and id of the creating and created processes.
# Checks if the creating process is a malware.
# If the creating process is a malicious one, the created process will also be considered as corrupted.
# If the new malware is already known adds the created pid to that object after having checked
# that the created pid is not already a valid pid for that malicious process.
# Else create a new malware object and initialize it with the created pid.
def is_creating_process(line, filename):
    commas = line.strip().split(',')
    creating_pid = int(commas[2].strip())
    creating_name = commas[3].split(')')[0].strip()
    created_pid = int(commas[5].strip())
    created_name = commas[6].split(')')[0].strip()

    malware = is_db_malware(creating_name, filename)
    if not malware:
        malware = is_corrupted_process(creating_name, filename)

    if malware and malware.is_valid_pid(creating_pid) and malware.has_active_pid() \
            and malware.get_active_pid() == creating_pid:
        target = is_db_malware(created_name, filename)
        if not target:
            target = is_corrupted_process(created_name, filename)
        if target:
            if not target.is_valid_pid(created_pid):
                target.add_pid(created_pid, Malware.CREATED)
            return
        new_malware = domain_utils.initialize_malware_object(filename, created_name, db_file_malware_dict, file_corrupted_processes_dict)
        new_malware.add_pid(created_pid, Malware.CREATED)
