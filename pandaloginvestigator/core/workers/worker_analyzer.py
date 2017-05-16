from pandaloginvestigator.core.domain.corrupted_process_object import CorruptedProcess
from pandaloginvestigator.core.domain.sample_object import Sample
from pandaloginvestigator.core.domain.sample_object import ReducedSample
from pandaloginvestigator.core.io import file_output
from pandaloginvestigator.core.utils import panda_utils
from pandaloginvestigator.core.utils import string_utils
import traceback
import logging
import os
import time

"""
Worker process in charge of analyzing the pandalog files. 
"""

# Global Variables
logger = logging.getLogger(__name__)
current_sample = None
dir_unpacked_path = None
dir_analyzed_logs = None
system_call_dict = {}


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
     * dictionary mapping each system call code to its mnemonic value - 8
     * dictionary containing dangerous registry keys and values - 9
    
    :param data_pack: data needed by the worker 
    :return: dictionary of analyzed samples
    """

    global current_sample, system_call_dict, dir_unpacked_path, dir_analyzed_logs
    j = 0.0
    starting_time = time.time()

    # Unpacking of the passed data
    worker_id = data_pack[0]
    file_names = data_pack[1]
    db_file_malware_name_map = data_pack[2]
    dir_unpacked_path = data_pack[3]
    dir_analyzed_logs = data_pack[4]
    small_disk = data_pack[5]
    dir_panda_path = data_pack[6]
    dir_pandalogs_path = data_pack[7]
    system_call_dict = data_pack[8]

    # the analyzed samples dictionary maps pandalog uuids with the related Sample object
    analyzed_samples = {}
    number_pandalogs = len(file_names)
    logger.info('WorkerId {} analyzing {} log files'.format(worker_id, number_pandalogs))

    for file_name in file_names:
        if small_disk:
            panda_utils.unpack_log(dir_panda_path, file_name + '.plog', dir_pandalogs_path, dir_unpacked_path)

        if file_name in db_file_malware_name_map:
            current_sample = Sample(file_name, db_file_malware_name_map[file_name])
            analyze_log(file_name)

            # Used to track activity windows of corrupted process at end of log
            if current_sample.active_corrupted_process:
                current_sample.active_corrupted_process.activity_ranges.append(
                    (current_sample.active_corrupted_process.last_starting_instruction, - 1)
                )
            current_sample.total_activity_ranges()

            reduced_sample = ReducedSample(current_sample)
            analyzed_samples[file_name] = reduced_sample

            file_output.output_json(file_name, current_sample, dir_analyzed_logs)
        else:
            logger.error(str(worker_id) + ' ERROR sample uuid not in db: ' + str(file_name))

        if small_disk:
            panda_utils.remove_log_file(file_name, dir_unpacked_path)

        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / number_pandalogs)))

    total_time = time.time() - starting_time
    logger.info('WorkerId ' + str(worker_id) + ' Total time: ' + str(total_time))
    return analyzed_samples


def analyze_log(file_name):
    """
    Analyze the log file line by line. Checks if each line contains:
     * context switch
     * process creation
     * memory write
     * file write
     * process sleep
     * process termination
     * crashes
     * error raising    
    At the end output a file with the results for the single pandalog.
    Performance optimization: if no corrupted process is currently active there is no need to analyze the line.
 
    :param file_name: uuid of the pandalog to analyze
    :return:
    """

    global current_sample

    # Performance optimization
    tag_access_key = string_utils.tag_access_key
    tag_query_key = string_utils.tag_query_key
    tag_context_switch = string_utils.tag_context_switch
    tag_system_call = string_utils.tag_system_call
    tag_termination = string_utils.tag_termination
    tag_process_creation = string_utils.tag_process_creation
    tag_write_memory = string_utils.tag_write_memory
    tag_read_memory = string_utils.tag_read_memory
    tag_write_file = string_utils.tag_write_file
    error_manager = string_utils.error_manager

    # Read the log file line by line
    with open(os.path.join(dir_unpacked_path, file_name), 'r', encoding='utf-8', errors='replace') as logfile:
        for line in logfile:
            try:
                if tag_context_switch in line:
                    context_switch(line)
                elif tag_read_memory in line and error_manager in line:
                    crashing(line)
                elif not current_sample.active_corrupted_process:
                    continue
                elif tag_system_call in line:
                    system_call(line)
                elif tag_process_creation in line:
                    creating_process(line)
                elif tag_write_memory in line:
                    writing_memory(line)
                elif tag_write_file in line:
                    writing_file(line)
                elif any(tag in line for tag in tag_access_key):
                    open_registry_key(line)
                elif tag_query_key in line:
                    query_registry_key(line)
                elif tag_termination in line:
                    terminating_process(line)
            except:
                traceback.print_exc()


def get_corrupted_process(process_name, pid):
    """
    Checks if the process name and pid retrieved correspond to a corrupted process in the current sample.
    If found returns the corrupted process object.

    :param process_name: name of the process
    :param pid: pid of the process
    :return: Malware object if found, else None
    """

    global current_sample

    entering_process_info = (process_name, pid)

    # If the process is already known to be corrupted return the related object
    if entering_process_info in current_sample.corrupted_processes:
        return current_sample.corrupted_processes[entering_process_info]

    # Otherwise checks if it is the original analyzed process and creates a new corrupted process object
    elif process_name == current_sample.malware_name:
        corrupted_process = CorruptedProcess(entering_process_info, CorruptedProcess.FROM_DB, entering_process_info)
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

    global current_sample

    current_instruction, pid, process_name = panda_utils.data_from_line(line)

    corrupted_process = get_corrupted_process(process_name, pid)

    if current_sample.active_corrupted_process:
        update_process_instruction_count(current_instruction)

    if corrupted_process:
        corrupted_process.last_starting_instruction = current_instruction
        current_sample.active_corrupted_process = corrupted_process


def update_process_instruction_count(current_instruction):
    """
    Updates the instruction count of a malicious process once it is context switched out of the CPU.
    It is called only if the current sample has an active corrupted process.
    After the update, set the active corrupted process to None.

    :param current_instruction: current instruction number
    :return:
    """

    global current_sample

    corrupted_process = current_sample.active_corrupted_process

    starting_instruction = corrupted_process.last_starting_instruction
    instruction_delta = current_instruction - starting_instruction
    corrupted_process.instruction_executed += instruction_delta

    corrupted_process.activity_ranges.append((starting_instruction, current_instruction))

    current_sample.active_corrupted_process = None


def terminating_process(line):
    """
    Handles termination system calls.
    Finds out process name and id of the terminating and terminated processes.
    Checks if terminating process is corrupted and if so updates its termination information.
    A corrupted process may terminate any process in the system (not only corrupted ones), if the terminated process
    was corrupted, updates its termination status.

    :param line: the current pandalog line
    :return:
    """

    global current_sample

    current_instruction, terminating_pid, terminating_name, terminated_pid, terminated_name = panda_utils.data_from_line_double(
        line)

    corrupted_process = get_corrupted_process(terminating_name, terminating_pid)

    if corrupted_process:
        terminated_process_info = (terminated_name, terminated_pid)
        corrupted_process.terminated_processes.add(terminated_process_info)

        if terminated_process_info in current_sample.corrupted_processes:
            current_sample.corrupted_processes[terminated_process_info].terminated = True


def crashing(line):
    """
    Checks if the error manager WerFault.exe is reading memory of one of a corrupted process.
    If so it means that the process has crashed.

    :param line: the current pandalog line
    :return:
    """

    # Acquire information on process being read by WerFault.exe
    commas = line.strip().split(',')
    read_pid = int(commas[5].strip())
    read_name = commas[6].split(')')[0].strip()

    corrupted_process = get_corrupted_process(read_name, read_pid)

    if corrupted_process:
        corrupted_process.crashed = True


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

    global current_sample

    current_instruction, creating_pid, creating_name, created_pid, created_name, new_path = panda_utils.data_from_line_double(
        line, creating=True)

    creating_process_info = (creating_name, creating_pid)
    corrupted_process = get_corrupted_process(creating_name, creating_pid)

    if corrupted_process:
        created_process_info = (created_name, created_pid)

        # Some chains of creation/termination may end up generating colliding (name, pid) couples
        if created_process_info in current_sample.corrupted_processes:
            return

        created_process = CorruptedProcess(created_process_info, CorruptedProcess.CREATED, creating_process_info)
        corrupted_process.created_processes.add((created_process_info, new_path))
        current_sample.corrupted_processes[created_process_info] = created_process


def writing_memory(line):
    """
    Handles the write on virtual memory system calls.
    Finds out process name and id of the writing and written processes.
    Checks if the writing process is a corrupted, if so:
     * updates its memory writing information
     * the written process will also be considered as corrupted
     * creates a new corrupted process object.

    :param line: the current pandalog line
    :return:
    """

    global current_sample

    current_instruction, writing_pid, writing_name, written_pid, written_name = panda_utils.data_from_line_double(line)

    writing_process_info = (writing_name, writing_pid)
    corrupted_process = get_corrupted_process(writing_name, writing_pid)

    if corrupted_process:
        written_process_info = (written_name, written_pid)

        # Corrupted processes may write multiple times on the memory of another process
        if written_process_info in current_sample.corrupted_processes:
            return

        written_process = CorruptedProcess(written_process_info, CorruptedProcess.WRITTEN, writing_process_info)
        corrupted_process.written_memory.add(written_process_info)
        current_sample.corrupted_processes[written_process_info] = written_process


def writing_file(line):
    """
    Handles the write on file system calls. 
    Finds out the writers id and process name. 
    Checks if the writing process is corrupted and, if so, updates its file writing information.

    :param line: the current pandalog line
    :return:
    """

    current_instruction, pid, process_name, written_file_path = panda_utils.data_from_line(line, writing=True)

    corrupted_process = get_corrupted_process(process_name, pid)

    if corrupted_process:
        corrupted_process.written_file.add(written_file_path)


def system_call(line):
    """
    Handles general system calls executed.
    In particular keeps track of sleep calls and error raising.
    
    :param line: the current pandalog line
    :return: 
    """

    global current_sample
    corrupted_process = current_sample.active_corrupted_process

    # Numerical codes for sleep and error system calls
    sleep_code = 98
    error_code = 272

    system_call_code = int(line.split('=')[3][:-2])

    if system_call_code == sleep_code:
        corrupted_process.sleep = True
    elif system_call_code == error_code:
        corrupted_process.error = True

    corrupted_process.syscalls_executed += 1
    syscall_mnemonic = system_call_dict.get(system_call_code, 'unknown')
    corrupted_process.system_calls[syscall_mnemonic] = corrupted_process.system_calls.get(syscall_mnemonic, 0) + 1


def open_registry_key(line):
    """
    Collects information about registry keys opened by corrupted processes
    
    :param line: the current pandalog line
    :return: 
    """

    current_instruction, pid, process_name, registry_key = panda_utils.data_from_line(line, registry=True)

    corrupted_process = get_corrupted_process(process_name, pid)

    if corrupted_process:
        if registry_key not in corrupted_process.registry_activity:
            corrupted_process.registry_activity[registry_key] = set()


def query_registry_key(line):
    """
    Collects information about registry keys opened by corrupted processes
    
    :param line: the current pandalog line
    :return: 
    """

    current_instruction, pid, process_name, registry_key, query = panda_utils.data_from_line(line, registry_query=True)

    corrupted_process = get_corrupted_process(process_name, pid)

    if corrupted_process:
        # Processes whose memory have been overwritten may still have open registry keys
        if registry_key not in corrupted_process.registry_activity:
            corrupted_process.registry_activity[registry_key] = set()

        corrupted_process.registry_activity[registry_key].add(query)
