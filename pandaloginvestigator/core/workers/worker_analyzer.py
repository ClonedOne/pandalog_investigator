from pandaloginvestigator.core.domain.corrupted_process_object import CorruptedProcess
from pandaloginvestigator.core.domain.sample_object import Sample
from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import panda_utils
import traceback
import logging
import time
import os

"""
Worker process in charge of analyzing the pandalog files. 
"""

# Global Variables
logger = logging.getLogger(__name__)
current_sample = None
dir_unpacked_path = None
dir_analyzed_logs = None

# Performance optimization
tag_context_switch = string_utils.tag_context_switch
tag_termination = string_utils.tag_termination
tag_process_creation = string_utils.tag_process_creation
tag_write_memory = string_utils.tag_write_memory
tag_read_memory = string_utils.tag_read_memory
tag_sleep = string_utils.tag_sleep
tag_raise_error = string_utils.tag_raise_error
tag_write_file = string_utils.tag_write_file
error_manager = string_utils.error_manager


def work(data_pack):
    """
    Pandalog analysis worker main method. The data passed to each worker contains:
     * worker id - 0
     * list of file names to analyze - 1
     * dictionary containing the original malware process name (md5) for each file uuid - 2
     * path to the unpacked pandalog files - 3
     * path to the analyzed logs directory - 4
     * flag indicating the need to delete unpacked files after analysis - 5
     * path to the pandalog unpacker utility - 6
     * path to the compressed pandalog files - 7
    
    :param data_pack: data needed by the worker 
    :return: set of analyzed samples
    """

    global current_sample, dir_unpacked_path, dir_analyzed_logs
    starting_time = time.time()
    j = 0.0

    # Unpacking of the passed data
    worker_id = data_pack[0]
    filenames = data_pack[1]
    db_file_malware_name_map = data_pack[2]
    dir_unpacked_path = data_pack[3]
    dir_analyzed_logs = data_pack[4]
    small_disk = data_pack[5]
    dir_panda_path = data_pack[6]
    dir_pandalogs_path = data_pack[7]

    analyzed_samples = set()
    number_pandalogs = len(filenames)
    logger.info('WorkerId {} analyzing {} log files'.format(worker_id, number_pandalogs))

    for filename in filenames:
        if small_disk:
            panda_utils.unpack_log(dir_panda_path, filename + '.txz.plog', dir_pandalogs_path, dir_unpacked_path)

        if filename in db_file_malware_name_map:
            current_sample = Sample(filename, db_file_malware_name_map[filename])
            analyzed_samples.add(current_sample)
            analyze_log(filename)
        else:
            logger.error(str(worker_id) + ' ERROR filename not in db: ' + str(filename))

        if small_disk:
            panda_utils.remove_log_file(filename, dir_unpacked_path)

        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / number_pandalogs)))

    total_time = time.time() - starting_time
    logger.info('WorkerId ' + str(worker_id) + ' Total time: ' + str(total_time))
    return analyzed_samples


def analyze_log(filename):
    """
    Analyze the log file line by line. Checks if each line contains a context switch, a process creation, 
    a memory write or a process termination. At the end output a file with the results for the single pandalog.
 
    :param filename: uuid of the pandalog to analyze
    :return:
    """

    with open(os.path.join(dir_unpacked_path, filename), 'r', encoding='utf-8', errors='replace') as logfile:
        for line in logfile:
            try:
                if tag_context_switch in line:
                    context_switch(line)
                elif tag_process_creation in line:
                    creating_process(line, filename)
                elif tag_write_memory in line:
                    is_writing_memory(line, filename)
                elif tag_write_file in line:
                    is_writing_file(line, filename)
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
                # terminating_all = terminates_all(filename)
                # sleeping_all = calls_sleep_on_all(filename)
                # crashing_all = is_crashing_all(filename)
                # error_all = is_raising_error_all(filename)
                # writes_file = writes_at_least_one_file(filename)
                # file_utils.output_on_file_instructions(
                #     filename,
                #     process_dict,
                #     inverted_process_dict,
                #     dir_analyzed_logs,
                #     db_file_malware_dict,
                #     file_corrupted_processes_dict,
                #     terminating_all,
                #     sleeping_all,
                #     crashing_all,
                #     error_all,
                #     writes_file
                # )


def calls_sleep_on_all(filename):
    """
    Checks if the malware_objects associated with the filename have called the
    sleep function on all their processes.

    :param filename:
    :return: True if all processes called sleep, else False
    """
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


def terminates_all(filename):
    """
    Checks if the malware_objects associated with the filename have terminated
    all their processes.

    :param filename:
    :return: True if all processes terminated, else False
    """
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


def writes_at_least_one_file(filename):
    """
    Checks if the malware_objects associated with the filename have written
    at least one file in all their processes.

    :param filename:
    :return:
    """
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        pid_list = malware.get_pid_list()
        for pid in pid_list:
            if malware.get_written_files(pid):
                file_writefile_dict[filename] = True
                return True
    if filename in file_corrupted_processes_dict:
        malwares = file_corrupted_processes_dict[filename]
        for malware in malwares:
            pid_list = malware.get_pid_list()
            for pid in pid_list:
                if malware.get_written_files(pid):
                    file_writefile_dict[filename] = True
                    return True

    file_writefile_dict[filename] = False
    return False


def is_crashing_all(filename):
    """
    Checks if the malware_objects associated with the filename have crashed all
    their processes.

    :param filename:
    :return: True if all processes have creshed, else False
    """
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


def is_raising_error_all(filename):
    """
    Checks if the malware_objects associated with the filename have raised hard
    errors for all their processes.

    :param filename:
    :return: True if all processes have raised errors, else False
    """
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


def is_corrupted_process(process_name, pid):
    """
    Checks if the process name and pid retrieved correspond to a corrupted process in the current sample.
    If found returns the corrupted process object.

    :param process_name: name of the process
    :param pid: pid of the process
    :return: Malware object if found, else None
    """

    entering_process_info = (process_name, pid)

    # If the process is already known to be corrupted return the related object
    if entering_process_info in current_sample.corrupted_processes:
        return current_sample.corrupted_processes[entering_process_info]

    # Otherwise checks if it is the original analyzed process and creates a new corrupted process object
    elif process_name == current_sample.malware_name:
        corrupted_process = CorruptedProcess(entering_process_info, string_utils.FROM_DB, entering_process_info)
        current_sample.corrupted_processes[entering_process_info] = corrupted_process
        return corrupted_process

    # If none of the above is true then the entering process is clean
    else:
        return None


def context_switch(line):
    """
    Called upon context switch, this method gathers information on which processes are going in/out of CPU.
    It gets the process id and process name of the new process and the current value of the instruction counter. 
    If the process exiting CPU is corrupted, updates that corrupted process instruction count.
    If the process entering CPU is corrupted, updates its starting instruction and sets it as new active corrupted 
    process for the current sample.

    :param line: current line in the log file
    :return:
    """

    current_instruction, pid, process_name = panda_utils.data_from_line_basic(line)

    corrupted_process = is_corrupted_process(process_name, pid)

    if current_sample.active_corrupted_process:
        update_process_instruction_count(current_instruction)

    if corrupted_process:
        corrupted_process.starting_instruction = current_instruction
        current_sample.active_corrupted_process = corrupted_process


def update_process_instruction_count(current_instruction):
    """
    Updates the instruction count of a malicious process once it is context switched out of the CPU.
    It is called only if the current sample has an active corrupted process.
    After the update, set the active corrupted process to None.

    :param current_instruction:
    :return:
    """

    corrupted_process = current_sample.active_corrupted_process

    starting_instruction = corrupted_process.starting_instruction
    instruction_delta = current_instruction - starting_instruction
    corrupted_process.instruction_executed += instruction_delta

    current_sample.active_corrupted_process = None


def is_terminating(line, filename):
    """
    Handles termination system calls. Analyze the log to find out process name
    and id of the terminating and terminated processes. Checks if terminating
    process is a malware and if so updates malware's termination information.

    :param line:
    :param filename:
    :return:
    """
    current_instruction, terminating_pid, terminating_name, terminated_pid, terminated_name = panda_utils.data_from_line(
        line)

    malware = is_db_malware(terminating_name, filename)
    if not malware:
        malware = is_corrupted_process(terminating_name, terminating_pid, filename)
    if malware and malware.is_valid_pid(terminating_pid) and malware.has_active_pid() and malware.is_active_pid(
            terminating_pid):
        malware.add_terminated_process(
            terminating_pid,
            terminated_pid,
            terminated_name,
            current_instruction
        )


def is_calling_sleep():
    """
    Handles NtDelayExecution system calls. The purpose is to understand if the
    malicious process is trying to hide itself by calling the sleep function for
    enough time to avoid examination.

    :return:
    """
    global active_malware
    if active_malware:
        malware = active_malware
        if malware:
            active_pid = malware.get_active_pid()
            malware.add_sleep(active_pid)


def is_raising_error():
    """
    Handles NtRaiseHardError system calls. It is used to understand if a malware
    process is raising an unrecoverable error due for instance to the missing of
    a required dll.

    :return:
    """
    global active_malware
    if active_malware:
        malware = active_malware
        if malware:
            active_pid = malware.get_active_pid()
            malware.add_error(active_pid)


def is_crashing(line, filename):
    """
    Checks if the error manager WerFault.exe is reading memory of one of the
    malware's processes. If so it may mean the process has crashed.+

    :param line:
    :param filename:
    :return:
    """
    commas = line.strip().split(',')
    read_pid = int(commas[5].strip())
    read_name = commas[6].split(')')[0].strip()
    malware = is_db_malware(read_name, filename)
    if not malware:
        malware = is_corrupted_process(read_name, read_pid, filename)

    if malware and malware.is_valid_pid(read_pid):
        if not malware.get_crash(read_pid):
            malware.add_crash(read_pid)


def creating_process(line):
    """
    Handles process creation system calls.
    Finds out process name and id of the creating and created processes. 
    Checks if the creating process is corrupted, if so:
     * updates its creation information
     * the created process will also be considered as corrupted
     * creates a new corrupted process object
     * the path for the executable of the created process is gathered through the method get_new_path().

    :param line: the current pandalog line
    :return:
    """

    current_instruction, creating_pid, creating_name, created_pid, created_name, new_path = panda_utils.data_from_line(
        line, creating=True)

    creating_process_info = (creating_name, creating_pid)
    corrupted_process = is_corrupted_process(creating_name, creating_pid)

    if corrupted_process:
        created_process_info = (created_name, created_pid)
        corrupted_process.created_processes.append(created_process_info)
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
                target.add_pid(created_pid, CorruptedProcess.CREATED, (creating_name, creating_pid))
            return

        new_malware = domain_utils.initialize_malware_object(
            filename,
            created_name,
            db_file_malware_dict,
            file_corrupted_processes_dict
        )
        new_malware.add_pid(created_pid, CorruptedProcess.CREATED, (creating_name, creating_pid))


def is_writing_memory(line, filename):
    """
    Handles the write on virtual memory system calls. Analyze the log to find
    out process name and id of the writing and written processes. Checks if the
    writing process is a malware and, if so, updates the malware memory writing
    information. If the writing process is a malicious one, the written process
    will also be considered as corrupted. If the new malware is already known
    adds the written pid to that object after having checked that the written
    pid is not already a valid pid for that malicious process. Else create a new
    malware object and initialize it with the written pid.

    :param line:
    :param filename:
    :return:
    """
    current_instruction, writing_pid, writing_name, written_pid, written_name = panda_utils.data_from_line(line)

    malware = is_db_malware(writing_name, filename)
    if not malware:
        malware = is_corrupted_process(writing_name, writing_pid, filename)

    if malware and malware.is_valid_pid(writing_pid) and malware.has_active_pid() and malware.is_active_pid(
            writing_pid):
        malware.add_written_memory(
            writing_pid,
            written_pid,
            written_name,
            current_instruction
        )

        target = is_db_malware(written_name, filename)
        if not target:
            target = is_corrupted_process(written_name, written_pid, filename)

        if target:
            if not target.is_valid_pid(written_pid):
                target.add_pid(written_pid, CorruptedProcess.WRITTEN, (writing_name, writing_pid))
            return
        new_malware = domain_utils.initialize_malware_object(
            filename,
            written_name,
            db_file_malware_dict,
            file_corrupted_processes_dict
        )
        new_malware.add_pid(written_pid, CorruptedProcess.WRITTEN, (writing_name, writing_pid))


def is_writing_file(line, filename):
    """
    Handles the write on file system calls. Finds out the writers id and
    process name. Checks if the writing process is a malware and, if so,
    updates the malware file writing information.

    :param line:
    :param filename:
    :return:
    """
    current_instruction, subject_pid, subject_name = panda_utils.data_from_line_basic(line)

    malware = is_db_malware(subject_name, filename)
    if not malware:
        malware = is_corrupted_process(subject_name, subject_pid, filename)

    if malware and malware.has_active_pid() and malware.is_active_pid(subject_pid):
        malware.add_written_file(subject_pid)
