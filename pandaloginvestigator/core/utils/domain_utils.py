from pandaloginvestigator.core.domain.corrupted_process_object import CorruptedProcess
from pandaloginvestigator.core.domain.sample_object import Sample
from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils
import logging

"""
This module handles utility methods which are inherently related to the domain of the application. Therefore this
module has explicit knowledge of domain's structure.
"""

logger = logging.getLogger(__name__)


# Utilities related to system calls.

def get_syscalls():
    """
    Use the provided table of system calls to generate a system call number -> system call name dictionary. Reference
    system is Windows 7 SP 01.

    :return: dictionary of system calls
    """
    syscall_dict = {}
    with open('syscalls.tsv', 'r', encoding='utf-8', errors='replace') as syscall_file:
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
    Merge two clues object returning a new clue object containing all the elements present in the original objects

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
