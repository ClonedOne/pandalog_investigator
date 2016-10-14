from pandaloginvestigator.core.domain.malware_object import Malware
from pandaloginvestigator.core.domain.clues import Clues
from pandaloginvestigator.core.utils import string_utils


# This module handles utility methods which are inherently related to the
# domain of the application. Therefore this module has explicit knowledge
# of domain's structure.


# Utilities related to Malware class.

# Utility method to initialize a new malware object given the relative process
# name and file name. Checks whether the new process would be the db_malware
# or a corrupted process.
def initialize_malware_object(filename, malware_name, db_file_malware_dict, file_corrupted_processes_dict, from_db=False):
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


# Returns a string representation of the specified malware object.
def repr_malware(malware):
    result = ''
    for pid in malware.get_pid_list():
        result += '{} {:20s}\n'.format(string_utils.proc_name, malware.name)
        result += '{} {:20d}\n'.format(string_utils.proc_pid, pid)
        result += '{} {:20s}\n'.format(string_utils.proc_orig, malware.get_origin(pid))
        result += '{} {:20d}\n'.format(string_utils.last_inst, malware.get_starting_instruction(pid))
        result += '{} {:20d}\n'.format(string_utils.exec_inst, malware.get_instruction_executed(pid))

        result += '\n{}\n'.format(string_utils.text_spawned)
        for entry in malware.get_spawned_processes(pid):
            for sub_entry in entry:
                result += str(sub_entry) + '\t'
            result += '\n'

        result += '\n{}\n'.format(string_utils.text_terminated)
        for entry in malware.get_terminated_processes(pid):
            for sub_entry in entry:
                result += str(sub_entry) + '\t'
            result += '\n'
        result += '\n{}\n'.format(string_utils.text_written)
        for entry in malware.get_written_memories(pid):
            for sub_entry in entry:
                result += str(sub_entry) + '\t'
            result += '\n'

        result += '\n{} {:10d}\n'.format(string_utils.text_sleep, malware.get_sleep(pid))
        result += '{} {} {}\n\n'.format(string_utils.text_crash_missing_dll, malware.get_crash(pid), malware.get_error(pid))

    executed = malware.get_total_executed_instructions()
    result += string_utils.text_executed + '\n'
    result += '{:15d} {:15d} {:15d} {:15d}\n\n\n'.format(executed[0], executed[1], executed[2], executed[3])
    return result


# Returns a list of the processes names and ids of the specified malware as
# a string.
def repr_malware_processes(malware):
    result = ''
    pid_list = malware.pid_list
    name = malware.name
    for pid in pid_list:
        parent = malware.get_parent_of(pid)
        result += '\t\t{:15s}\t{:10d}\t{:15s}\tby:\t{:15s}\t{:10d}\n'.format(name, pid, malware.origin[pid], parent[0], parent[1])
    return result


# Utilities related to system calls.

# Use the provided table of system calls to generate a system call number -> system call name dictionary.
# Reference system is Windows 7 SP 01.
def get_syscalls():
    syscall_dict = {}
    with open('syscalls.tsv') as syscall_file:
        for line in syscall_file:
            line = line.split('\t')
            syscall_dict[int(line[0])] = line[1].strip()
    return syscall_dict


# Utilities related to Suspect class.

# Provide a string representation of the suspect object.
def repr_clue(clue):
    result = '{} {}\n'.format(string_utils.filename, clue.get_filename())
    opened_keys = clue.get_opened_keys()
    queried_values = clue.get_queries_key_values()
    for malware in opened_keys:
        proc_name = malware[0]
        proc_id = malware[1]
        mal_opened_keys = opened_keys[malware]
        for key, occurrency in mal_opened_keys.items():
            result += '{:15s}\t{:85s}\t{:10d}\tby\t{}\t{}\n'.format(
                string_utils.opened,
                key,
                occurrency,
                proc_name,
                proc_id
            )
    for malware in queried_values:
        proc_name = malware[0]
        proc_id = malware[1]
        mal_queried_values = queried_values[malware]
        for value, occurrency in mal_queried_values.items():
            result += '{:15s}\t{:85s}\t{:10d}\tby\t{}\t{}\n'.format(
                string_utils.queried,
                value,
                occurrency,
                proc_name,
                proc_id
            )

    return result
