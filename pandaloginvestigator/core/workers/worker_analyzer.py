from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.utils import panda_utils
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.domain.malware_object import Malware
import logging
import time
import traceback


logger = logging.getLogger(__name__)
dir_unpacked_path = None
dir_analyzed_logs = None
active_malware = None

tag_context_switch = string_utils.tag_context_switch
tag_termination = string_utils.tag_termination
tag_process_creation = string_utils.tag_process_creation
tag_write_memory = string_utils.tag_write_memory
tag_read_memory = string_utils.tag_read_memory
tag_sleep = string_utils.tag_sleep
tag_raise_error = string_utils.tag_raise_error
error_manager = string_utils.error_manager

file_corrupted_processes_dict = {}
db_file_malware_dict = {}
file_terminate_dict = {}
file_sleep_dict = {}
file_crash_dict = {}
file_error_dict = {}


def work(data_pack):
    t0 = time.time()
    global active_malware, dir_unpacked_path, dir_analyzed_logs
    j = 0.0
    worker_id = data_pack[0]
    filenames = data_pack[1]
    db_file_malware_name_map = data_pack[2]
    dir_unpacked_path = data_pack[3]
    dir_analyzed_logs = data_pack[4]
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId ' + str(worker_id) + ' analyzing ' + str(total_files) + ' log files')
    for filename in filenames:
        active_malware = None
        if filename in db_file_malware_name_map:
            domain_utils.initialize_malware_object(
                filename,
                db_file_malware_name_map[filename],
                db_file_malware_dict,
                file_corrupted_processes_dict,
                from_db=True)
            analyze_log(filename)
        else:
            logger.error(str(worker_id) + ' ERROR filename not in db')
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
    total_time = time.time() - t0
    logger.info('WorkerId ' + str(worker_id) + ' Total time: ' + str(total_time))
    return db_file_malware_dict, file_corrupted_processes_dict, file_terminate_dict, file_sleep_dict, file_crash_dict, file_error_dict


# Checks if the malware_objects associated with the filename have called the
# sleep function on all their processes.
def is_sleeping_all(filename):
    all_pids = set()
    all_sleep = set()
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        pid_list = malware.get_pid_list()
        malware_name = malware.get_name()
        for pid in pid_list:
            all_pids.add((malware_name, pid))
            sleep_count = malware.get_sleep(pid)
            if sleep_count:
                all_sleep.add((malware_name, pid))

    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            malware_name = malware.get_name()
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                all_pids.add((malware_name, pid))
                sleep_count = malware.get_sleep(pid)
                if sleep_count:
                    all_sleep.add((malware_name, pid))

    not_empty = len(all_pids) > 0
    if all_pids.issubset(all_sleep) and not_empty:
        file_sleep_dict[filename] = True
        return True
    else:
        file_sleep_dict[filename] = False
        return False


# Checks if the malware_objects associated with the filename have terminated
# all their processes.
def is_terminating_all(filename):
    all_pids = set()
    all_term = set()
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        malware_name = malware.get_name()
        pid_list = malware.get_pid_list()
        for pid in pid_list:
            all_pids.add((malware_name, pid))
            terms = malware.get_terminated_processes(pid)
            for term in terms:
                all_term.add((term[1], term[0]))

    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            malware_name = malware.get_name()
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                all_pids.add((malware_name, pid))
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


# Checks if the malware_objects associated with the filename have crashed all
# their processes.
def is_crashing_all(filename):
    all_pids = set()
    all_crash = set()
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        malware_name = malware.get_name()
        pid_list = malware.get_pid_list()
        for pid in pid_list:
            all_pids.add((malware_name, pid))
            crash_count = malware.get_crash(pid)
            if crash_count:
                all_crash.add((malware_name, pid))

    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            malware_name = malware.get_name()
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                all_pids.add((malware_name, pid))
                crash_count = malware.get_crash(pid)
                if crash_count:
                    all_crash.add((malware_name, pid))

    not_empty = len(all_pids) > 0
    if all_pids.issubset(all_crash) and not_empty:
        file_crash_dict[filename] = True
        return True
    else:
        file_crash_dict[filename] = False
        return False


# Checks if the malware_objects associated with the filename have raised hard
# errors for all their processes.
def is_raising_error_all(filename):
    all_pids = set()
    all_error = set()
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        malware_name = malware.get_name()
        pid_list = malware.get_pid_list()
        for pid in pid_list:
            all_pids.add((malware_name, pid))
            error_count = malware.get_error(pid)
            if error_count:
                all_error.add((malware_name, pid))

    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            malware_name = malware.get_name()
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                all_pids.add((malware_name, pid))
                error_count = malware.get_error(pid)
                if error_count:
                    all_error.add((malware_name, pid))

    not_empty = len(all_pids) > 0
    if all_pids.issubset(all_error) and not_empty:
        file_error_dict[filename] = True
        return True
    else:
        file_error_dict[filename] = False
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


# Checks if the process name is inside the file_corrupted_processes_dict. If
# positive also checks if the current pid corresponds to a valid pid for that
# malware That is because spawned or memory written processes may have the
# same name of correct processes in the system. Therefore the method looks
# only for valid couples name/pid. If found returns the malware.
def is_corrupted_process(proc_name, pid, filename):
    if filename not in file_corrupted_processes_dict:
        return None
    malwares = file_corrupted_processes_dict[filename]
    for malware in malwares:
        if malware.get_name() == proc_name and pid in malware.get_pid_list():
            return malware
    return None


# If a context switch happens this method is used to gather the information on
# which process is going in CPU. It gathers the process id and process name of
# the new process and the current value of the instruction counter. First it
# updates the related dictionaries with the new information. Then it tries to
# understand if the new process is a malware or a corrupted process. If it is
# a correct process and the previous process was a malware, update that
# malware instruction count. If it is a malware/corrupt process, update the
# instruction count of a previous malicious process (if there was one) and
# call the method is_malware().
def is_context_switch(filename, line, process_dict, inverted_process_dict):
    commas = line.strip().split(',')
    pid = int(commas[2].strip())
    proc_name = commas[3].split(')')[0].strip()
    current_instruction = int((commas[0].split()[0].split('='))[1])
    panda_utils.update_dictionaries(pid, process_dict, proc_name, inverted_process_dict)
    malware = is_db_malware(proc_name, filename)
    if not malware:
        malware = is_corrupted_process(proc_name, pid, filename)
    if active_malware:
        update_malware_instruction_count(current_instruction)
    if malware:
        is_malware(malware, pid, current_instruction)


# Updates the instruction count of a malicious process once it is context
# switched out of the CPU. It is called only if the active_malware is not
# None. It finds the active malware, updates its instruction count and
# deactivates its active pid. Then it sets active_malware to None.
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


# Handles termination system calls. Analyze the log to find out process name
# and id of the terminating and terminated processes. Checks if terminating
# process is a malware and if so updates malware's termination information.
def is_terminating(line, filename):
    current_instruction, terminating_pid, terminating_name, terminated_pid, terminated_name = panda_utils.data_from_line(line)

    malware = is_db_malware(terminating_name, filename)
    if not malware:
        malware = is_corrupted_process(terminating_name, terminating_pid, filename)
    if malware and malware.is_valid_pid(terminating_pid) and malware.has_active_pid() and malware.get_active_pid() == terminating_pid:
        malware.add_terminated_process(
            terminating_pid,
            terminated_pid,
            terminated_name,
            current_instruction
        )


# Handles NtDelayExecution system calls. The purpose is to understand if the
# malicious process is trying to hide itself by calling the sleep function for
# enough time to avoid examination.
def is_calling_sleep():
    global active_malware
    if active_malware:
        malware = active_malware
        if malware:
            active_pid = malware.get_active_pid()
            malware.add_sleep(active_pid)


# Handles NtRaiseHardError system calls. It is used to understand if a malware
# process is raising an unrecoverable error due for instance to the missing of
# a required dll.
def is_raising_error():
    global active_malware
    if active_malware:
        malware = active_malware
        if malware:
            active_pid = malware.get_active_pid()
            malware.add_error(active_pid)


# Checks if the error manager WerFault.exe is reading memory of one of the
# malware's processes. If so it may mean the process has crashed.
def is_crashing(line, filename):
    commas = line.strip().split(',')
    read_pid = int(commas[5].strip())
    read_name = commas[6].split(')')[0].strip()
    malware = is_db_malware(read_name, filename)
    if not malware:
        malware = is_corrupted_process(read_name, read_pid, filename)

    if malware and malware.is_valid_pid(read_pid):
        if not malware.get_crash(read_pid):
            malware.add_crash(read_pid)


# Handles process creation system calls. Analyze the log to find out process
# name and id of the creating and created processes. Checks if the creating
# process is a malware and if so updates the malware's creation information.
# If the creating process is a malicious one, the created process will also be
# considered as corrupted. If the new malware is already known adds the
# created pid to that object after having checked that the created pid is not
# already a valid pid for that malicious process. Else create a new malware
# object and initialize it with the created pid. The path for the executable
# of the created process is gathered through the method get_new_path().
def is_creating_process(line, filename):
    current_instruction, creating_pid, creating_name, created_pid, created_name, new_path = panda_utils.data_from_line(line, creating=True)
    malware = is_db_malware(creating_name, filename)
    if not malware:
        malware = is_corrupted_process(creating_name, creating_pid, filename)

    if malware and malware.is_valid_pid(creating_pid) and malware.has_active_pid() and malware.get_active_pid() == creating_pid:
        malware.add_spawned_process(
            creating_pid,
            created_pid,
            created_name,
            current_instruction,
            new_path
        )
        target = is_db_malware(created_name, filename)
        if not target:
            target = is_corrupted_process(created_name, created_pid, filename)
        if target:
            if not target.is_valid_pid(created_pid):
                target.add_pid(created_pid, Malware.CREATED, (creating_name, creating_pid))
            return
        new_malware = domain_utils.initialize_malware_object(
            filename,
            created_name,
            db_file_malware_dict,
            file_corrupted_processes_dict
        )
        new_malware.add_pid(created_pid, Malware.CREATED, (creating_name, creating_pid))


# Handles the write on virtual memory system calls. Analyze the log to find
# out process name and id of the writing and written processes. Checks if the
# writing process is a malware and if so updates the malware memory writing
# information. If the writing process is a malicious one, the written process
# will also be considered as corrupted. If the new malware is already known
# adds the written pid to that object after having checked that the written
# pid is not already a valid pid for that malicious process. Else create a new
# malware object and initialize it with the written pid.
def is_writing_memory(line, filename):
    current_instruction, writing_pid, writing_name, written_pid, written_name = panda_utils.data_from_line(line)
    malware = is_db_malware(writing_name, filename)
    if not malware:
        malware = is_corrupted_process(writing_name, writing_pid, filename)

    if malware and malware.is_valid_pid(writing_pid) and malware.has_active_pid() and malware.get_active_pid() == writing_pid:
        malware.add_written_memory(writing_pid, written_pid, written_name, current_instruction)
        target = is_db_malware(written_name, filename)
        if not target:
            target = is_corrupted_process(written_name, written_pid, filename)
        if target:
            if not target.is_valid_pid(written_pid):
                target.add_pid(written_pid, Malware.WRITTEN, (writing_name, writing_pid))
            return
        new_malware = domain_utils.initialize_malware_object(
            filename,
            written_name,
            db_file_malware_dict,
            file_corrupted_processes_dict
        )
        new_malware.add_pid(written_pid, Malware.WRITTEN, (writing_name, writing_pid))


# This method is called if the process being context switched inside CPU is a
# malicious one. Checks if the current pid is not already in the pid list of
# the malware. If it isn't, it means it is the first instruction of the
# db_malware. Therefore it adds the new pid value to the malware's list. Then
# it updates malware's starting instruction for that pid and set
# active_malware to specified malware.
def is_malware(malware, pid, current_instruction):
    global active_malware
    pid_list = malware.get_pid_list()
    if pid not in pid_list:
        malware.add_pid(pid, Malware.FROM_DB, (malware.get_name(), pid))
    malware.update_starting_instruction(pid, current_instruction)
    malware.activate_pid(pid)
    active_malware = malware


# Analyze the log file line by line. Checks if each line contains a context
# switch, a process creation, a memory write or a process termination. At the
# end print a summary of the analyzed mawlares on a file.
def analyze_log(filename):
    process_dict = {}
    inverted_process_dict = {}
    with open(dir_unpacked_path + '/' + filename, 'r', encoding='utf-8', errors='replace') as logfile:
        for line in logfile:
            try:
                if tag_context_switch in line:
                    is_context_switch(filename, line, process_dict, inverted_process_dict)
                elif tag_process_creation in line:
                    is_creating_process(line, filename)
                elif tag_write_memory in line:
                    is_writing_memory(line, filename)
                elif tag_sleep in line and active_malware:
                    is_calling_sleep()
                elif tag_termination in line:
                    is_terminating(line, filename)
                elif tag_read_memory in line and error_manager in line:
                    is_crashing(line, filename)
                elif tag_raise_error in line and active_malware:
                    is_raising_error()
            except:
                traceback.print_exc()
    terminating_all = is_terminating_all(filename)
    sleeping_all = is_sleeping_all(filename)
    crashing_all = is_crashing_all(filename)
    error_all = is_raising_error_all(filename)
    file_utils.output_on_file_instructions(
        filename,
        process_dict,
        inverted_process_dict,
        dir_analyzed_logs,
        db_file_malware_dict,
        file_corrupted_processes_dict,
        terminating_all,
        sleeping_all,
        crashing_all,
        error_all
    )
