from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import file_output
from pandaloginvestigator.core.utils import panda_utils
from pandaloginvestigator.core.domain.corrupted_process_object import CorruptedProcess
import logging
import time
import traceback


logger = logging.getLogger(__name__)
dir_unpacked_path = None
dir_syscall_path = None
active_malware = None

tag_context_switch = string_utils.tag_context_switch
tag_termination = string_utils.tag_termination
tag_process_creation = string_utils.tag_process_creation
tag_write_memory = string_utils.tag_write_memory
tag_system_call = string_utils.tag_system_call

file_corrupted_processes_dict = {}
db_file_malware_dict = {}
syscall_dict = {}


def work(data_pack):
    t0 = time.time()
    global active_malware, dir_unpacked_path, dir_syscall_path, syscall_dict
    j = 0.0
    filename_syscall_dict = {}
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path = data_pack[2]
    dir_syscall_path = data_pack[3]
    syscall_dict = data_pack[4]
    db_file_malware_name_map = data_pack[5]
    small_disk = data_pack[6]
    dir_panda_path = data_pack[7]
    dir_pandalogs_path = data_pack[8]
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId = ' + str(worker_id) + ' counting system calls on ' + str(total_files) + ' log files')
    for filename in filenames:
        if small_disk:
            panda_utils.unpack_log(dir_panda_path, filename + '.txz.plog', dir_pandalogs_path, dir_unpacked_path)
        active_malware = None
        if filename in db_file_malware_name_map:
            domain_utils.initialize_malware_object(filename, db_file_malware_name_map[filename],
                                                   db_file_malware_dict, file_corrupted_processes_dict, from_db=True)
            filename_syscall_dict[filename] = syscall_count(filename)
        else:
            logger.error(str(worker_id) + ' ERROR filename not in db')
        if small_disk:
            panda_utils.remove_log_file(filename, dir_unpacked_path)
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
    total_time = time.time() - t0
    logger.info(str(worker_id) + ' Total time: ' + str(total_time))
    return (filename_syscall_dict, )


def syscall_count(filename):
    """
    Analyze the log file line by line. Checks if each line contains a the tag of
    a systems call. If so update frequency of that system call.

    :param filename:
    :return: dictionary mapping system calls with their occurrences
    """
    malware_syscall_dict = {}
    with open(dir_unpacked_path + '/' + filename, 'r', encoding='utf-8', errors='replace') as logfile:
        for line in logfile:
            try:
                if tag_context_switch in line:
                    is_tag_context_switch(filename, line)
                elif tag_process_creation in line:
                    is_creating_process(line, filename)
                elif tag_write_memory in line:
                    is_writing_memory(line, filename)
                elif tag_system_call in line and active_malware:
                    system_call_num = int(line.split('=')[3].split(')')[0])
                    system_call = syscall_dict.get(system_call_num, system_call_num)
                    malware_syscall_dict[system_call] = malware_syscall_dict.get(system_call, 0) + 1
            except:
                traceback.print_exc()
    file_output.output_on_file_syscall(filename, dir_syscall_path, malware_syscall_dict, syscall_dict)
    return malware_syscall_dict


def is_tag_context_switch(filename, line):
    """
    If a context switch happens this method is used to gather the information on
    which process is going in CPU. It gathers the process id and process name of
    the new process and the current value of the instruction counter. Then it
    tries to understand if the new process is a malware or a corrupted process.

    :param filename:
    :param line:
    :return:
    """
    current_instruction, pid, proc_name = panda_utils.data_from_line_basic(line)

    malware = is_db_malware(proc_name, filename)
    if not malware:
        malware = is_corrupted_process(proc_name, pid, filename)

    if active_malware:
        deactivate_malware()
    if malware:
        is_malware(malware, pid)


def deactivate_malware():
    """
    It is called only if the active_malware is not None.
    It finds the active malware, deactivates its active pid.
    Then it sets active_malware to None.

    :return: 1 if success, else -1
    """
    global active_malware
    malware = active_malware
    active_pid = malware.get_active_pid()
    if active_pid == -1:
        return -1
    malware.deactivate_pid(active_pid)
    active_malware = None
    return 1


def is_malware(malware, pid):
    """
    This method is called if the process being context switched inside CPU is a
    malicious one. Checks if the current pid is not already in the pid list of
    the malware. If it isn't, it means it is the first instruction of the
    db_malware. Therefore it adds the new pid value to the malware's list. Then
    it updates malware's starting instruction for that pid and set
    active_malware to specified malware.

    :param malware:
    :param pid:
    :return:
    """
    global active_malware
    pid_list = malware.get_pid_list()
    if pid not in pid_list:
        malware.add_pid(pid, CorruptedProcess.FROM_DB, (malware.get_name(), pid))
    malware.activate_pid(pid)
    active_malware = malware


def is_writing_memory(line, filename):
    """
    Handles the write on virtual memory system calls. Analyze the log to find
    out process name and id of the writing and written processes. Checks if the
    writing process is a malware. If the writing process is a malicious one, the
    written process will also be considered as corrupted. If the new malware is
    already known adds the written pid to that object after having checked that
    the written pid is not already a valid pid for that malicious process. Else
    create a new malware object and initialize it with the written pid.

    :param line:
    :param filename:
    :return:
    """
    current_instruction, writing_pid, writing_name, written_pid, written_name = panda_utils.data_from_line(line)

    malware = is_db_malware(writing_name, filename)
    if not malware:
        malware = is_corrupted_process(writing_name, writing_pid, filename)

    if malware and malware.is_valid_pid(writing_pid) and malware.has_active_pid() and malware.get_active_pid() == writing_pid:

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


def is_creating_process(line, filename):
    """
    Handles process creation system calls. Analyze the log to find out process
    name and id of the creating and created processes. Checks if the creating
    process is a malware. If the creating process is a malicious one, the
    created process will also be considered as corrupted. If the new malware is
    already known adds the created pid to that object after having checked that
    the created pid is not already a valid pid for that malicious process. Else
    create a new malware object and initialize it with the created pid.

    :param line:
    :param filename:
    :return:
    """
    current_instruction, creating_pid, creating_name, created_pid, created_name, new_path = panda_utils.data_from_line(line, creating=True)

    malware = is_db_malware(creating_name, filename)
    if not malware:
        malware = is_corrupted_process(creating_name, creating_pid, filename)

    if malware and malware.is_valid_pid(creating_pid) and malware.has_active_pid() and malware.get_active_pid() == creating_pid:

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


def is_db_malware(proc_name, filename):
    """
    Checks if the process name is inside the db_file_malware_dict.
    This would mean that the current process is the original malware installed
    in the system. If found returns the malware.

    :param proc_name:
    :param filename:
    :return: Malware object if found, else None
    """
    if filename not in db_file_malware_dict:
        return None
    malware = db_file_malware_dict[filename]
    if malware.get_name() == proc_name:
        return malware
    else:
        return None


def is_corrupted_process(proc_name, pid, filename):
    """
    Checks if the process name is inside the file_corrupted_processes_dict. If
    positive also checks if the current pid corresponds to a valid pid for that
    malware That is because spawned or memory written processes may have the
    same name of correct processes in the system. Therefore the method looks
    only for valid couples name/pid. If found returns the malware.

    :param proc_name:
    :param pid:
    :param filename:
    :return: Malware object if found, else None
    """
    if filename not in file_corrupted_processes_dict:
        return None
    malwares = file_corrupted_processes_dict[filename]
    for malware in malwares:
        if malware.get_name() == proc_name and malware.is_valid_pid(pid):
            return malware
    return None
