from pandaloginvestigator.core.domain.malware_object import Malware
from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils
import logging


logger = logging.getLogger(__name__)

# This module handles utility methods which are inherently related to the
# domain of the application. Therefore this module has explicit knowledge
# of domain's structure.


# Utilities related to Malware class.

def initialize_malware_object(filename, malware_name, db_file_malware_dict, file_corrupted_processes_dict, from_db=False):
    """
    Utility method to initialize a new malware object given the relative process
    name and file name. Checks whether the new process would be the db_malware
    or a corrupted process.

    :param filename:
    :param malware_name:
    :param db_file_malware_dict:
    :param file_corrupted_processes_dict:
    :param from_db:
    :return: new Malware object
    """
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


def repr_malware(malware):
    """
    Returns a string representation of the specified malware object.

    :param malware:
    :return: string representing the whole malware
    """
    result = ''
    for pid in malware.get_pid_list():
        result += '{}\t{}\n'.format(string_utils.proc_name, malware.name)
        result += '{}\t{}\n'.format(string_utils.proc_pid, pid)
        result += '{}\t{}\n'.format(string_utils.proc_orig, malware.get_origin(pid))
        result += '{}\t{}\n'.format(string_utils.last_inst, malware.get_starting_instruction(pid))
        result += '{}\t{}\n'.format(string_utils.exec_inst, malware.get_instruction_executed(pid))
        result += '{}\t{}\n'.format(string_utils.text_sleep, malware.get_sleep(pid))

        result += '\n{}\n'.format(string_utils.text_spawned)
        result += '| {:20s} | {:20s} | {:20s} | {:20s} |\n'.format(
            'New pid',
            'Process name',
            'Instruction',
            'Executable path'
        )
        for entry in malware.get_spawned_processes(pid):
            for sub_entry in entry:
                result += '| {:20s} '.format(str(sub_entry))
            result += '|\n'

        result += '\n{}\n'.format(string_utils.text_terminated)
        result += '| {:20s} | {:20s} | {:20s} |\n'.format(
            'Terminated pid',
            'Process name',
            'Instruction'
        )
        for entry in malware.get_terminated_processes(pid):
            for sub_entry in entry:
                result += '| {:20s} '.format(str(sub_entry))
            result += '|\n'

        result += '\n{}\n'.format(string_utils.text_written)
        result += '| {:20s} | {:20s} | {:20s} |\n'.format(
            'Written pid',
            'Process name',
            'Instruction'
        )
        for entry in malware.get_written_memories(pid):
            for sub_entry in entry:
                result += '| {:20s} '.format(str(sub_entry))
            result += '|\n'

        result += '\n{}\n'.format(string_utils.text_spec_status)
        result += '| {:20s} | {:20s} | {:20s} |\n'.format(
            string_utils.text_crash,
            string_utils.text_raise_err,
            string_utils.text_written_file
        )
        result += '| {:20s} | {:20s} | {:20s} |\n\n'.format(
            str(malware.get_crash(pid)),
            str(malware.get_error(pid)),
            str(malware.get_written_files(pid))
        )

    executed = malware.get_total_executed_instructions()
    result += string_utils.text_executed + '\n'
    result += '| {:15s} | {:15s} | {:15s} | {:15s} |\n'.format('DB', 'created', 'memory written', 'total')
    result += '| {:15d} | {:15d} | {:15d} | {:15d} |\n\n\n'.format(executed[0], executed[1], executed[2], executed[3])
    return result


def repr_malware_processes(malware):
    """
    Returns a list of the processes names and ids of the specified malware as
    a string.

    :param malware:
    :return: string representing the malware processes
    """
    result = ''
    pid_list = malware.pid_list
    name = malware.name
    for pid in pid_list:
        parent = malware.get_parent_of(pid)
        result += '\t\t{:15s}\t{:10d}\t{:15s}\tby:\t{:15s}\t{:10d}\n'.format(name, pid, malware.origin[pid], parent[0], parent[1])
    return result


# Utilities related to system calls.


def get_syscalls():
    """
    Use the provided table of system calls to generate a system call number -> system call name dictionary.
    Reference system is Windows 7 SP 01.

    :return: dictionary of system calls
    """
    syscall_dict = {}
    with open('syscalls.tsv') as syscall_file:
        for line in syscall_file:
            line = line.split('\t')
            syscall_dict[int(line[0])] = line[1].strip()
    return syscall_dict


# Utilities related to Clues class.

def repr_clue(clue):
    """
    Provide a string representation of the suspect object.

    :param clue:
    :return:
    """
    result = '{} {}\n'.format(string_utils.filename, clue.get_filename())
    opened_keys = clue.get_opened_keys()
    queried_values = clue.get_queries_key_values()
    dangerous_inst = clue.get_dangerous_instructions()
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
    for malware in dangerous_inst:
        proc_name = malware[0]
        proc_id = malware[1]
        mal_dangerous_inst = dangerous_inst[malware]
        for inst, occurrency in mal_dangerous_inst.items():
            result += '{:15s}\t{:85s}\t{:10d}\tby\t{}\t{}\n'.format(
                string_utils.dangerous_instruction,
                inst,
                occurrency,
                proc_name,
                proc_id
            )
    return result


def read_clue(filename, lines):
    """
    Takes as imput the list of clue file lines and the file name
    and returns a clue object
    :param filename:
    :param lines:
    :return: new clue object
    """
    new_clue = Clue(filename)
    for line in lines:
        values = values_from_clues_regkey(line)
        kind = values[0]
        tag = values[1]
        counter = int(values[2])
        proc_name = values[4]
        proc_id = values[5]
        process = (proc_name, proc_id)
        if kind == string_utils.opened:
            new_clue.add_opened_key(process, tag, counter)
        if kind == string_utils.queried:
            new_clue.add_queried_key_value(process, tag, counter)
        if kind == string_utils.dangerous_instruction:
            new_clue.add_dangerous_instructions(process, tag, counter)
    return new_clue


def values_from_clues_regkey(line):
    """
    Returns the list of elements from a line of the output registry key clues file.

    :param line:
    :return: list of string elements of a registry key clue
    """
    line = line.strip()
    elems = line.split('\t')
    return [elem.strip() for elem in elems]


def merge_clues(clue1, clue2):
    """
    Merge two clues object returning a new clue object containing all
    the elements present in the original objects

    :param clue1:
    :param clue2:
    :return: new clue object
    """
    if clue1.get_filename() != clue2.get_filename():
        return None
    new_clue = Clue(clue1.get_filename())

    opened_keys1 = clue1.get_opened_keys()
    opened_keys2 = clue2.get_opened_keys()
    queried_values1 = clue1.get_queries_key_values()
    queried_values2 = clue2.get_queries_key_values()
    dangerous_inst1 = clue1.get_dangerous_instructions()
    dangerous_inst2 = clue2.get_dangerous_instructions()

    opened_keys = utils.merge_dict_dict(opened_keys1, opened_keys2)
    queried_values = utils.merge_dict_dict(queried_values1, queried_values2)
    dangerous_inst = utils.merge_dict_dict(dangerous_inst1, dangerous_inst2)

    new_clue.set_opened_keys(opened_keys)
    new_clue.set_queried_key_values(queried_values)
    new_clue.set_dangerous_instructions(dangerous_inst)

    return new_clue
