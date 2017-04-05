import logging
import os

import pandaloginvestigator.core.io.file_input
from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import string_utils

logger = logging.getLogger(__name__)


def read_data(dir_results_path, target):
    """
    Wrapper used to provide the correct data to both plotter methods.

    :param dir_results_path:
    :param target:
    :return:
    """
    if target == string_utils.target_i:
        return read_result_instr(dir_results_path)
    elif target == string_utils.target_s:
        return read_result_syscall(dir_results_path)


def read_result_instr(dir_results_path):
    """
    Read the instruction counting analysis result file in order to generate a list of dictionaries containing the
    values from the file.

    :param dir_results_path: path to the result folder
    :return: list of dictionaries
    """
    instr_totals_dict = {}
    instr_from_db_dict = {}
    created_dict = {}
    written_dict = {}
    terminating_dict = {}
    sleeping_dict = {}
    crashing_dict = {}
    error_dict = {}
    writefile_dict = {}
    file_path = dir_results_path + '/analysis.txt'
    with open(file_path, 'r', encoding='utf-8', errors='replace') as resfile:
        last_file_name = ''
        for line in resfile:
            if string_utils.filename in line:
                last_file_name = pandaloginvestigator.core.io.file_input.filename_from_analysis(line)
            elif string_utils.out_final in line:
                if line != string_utils.no_instructions:
                    values = pandaloginvestigator.core.io.file_input.values_from_analysis(line)
                    instr_from_db_dict[last_file_name] = int(values[0])
                    created_dict[last_file_name] = int(values[1])
                    written_dict[last_file_name] = int(values[2])
                    instr_totals_dict[last_file_name] = int(values[3])
            elif string_utils.out_terminating in line:
                status = pandaloginvestigator.core.io.file_input.status_from_analysis(line)
                terminating_dict[last_file_name] = status[0]
                sleeping_dict[last_file_name] = status[1]
                crashing_dict[last_file_name] = status[2]
                error_dict[last_file_name] = status[3]
                writefile_dict[last_file_name] = status[4]
    return [
        instr_totals_dict,
        instr_from_db_dict,
        created_dict,
        written_dict,
        terminating_dict,
        sleeping_dict,
        crashing_dict,
        error_dict,
        writefile_dict
    ]


def read_result_syscall(dir_results_path):
    """
    Read the system call counting result file in order to generate a dictionary containing the values from the file.

    :param dir_results_path: path to the result folder
    :return: list of dictionaries
    """
    syscalls_totals_dict = {}
    file_path = dir_results_path + '/syscalls.txt'
    with open(file_path, 'r', encoding='utf-8', errors='replace') as resfile:
        last_file_name = ''
        for line in resfile:
            if string_utils.filename in line:
                last_file_name = pandaloginvestigator.core.io.file_input.filename_from_analysis(line)
            elif string_utils.syscall_final in line:
                if line != string_utils.no_syscalls:
                    value = pandaloginvestigator.core.io.file_input.values_from_syscalls(line)
                    syscalls_totals_dict[last_file_name] = value
    return [syscalls_totals_dict, ]


def read_result_corrupted(dir_results_path: str) -> dict:
    """
    Reads the corrupted processes list form the results file in the specified directory. Returns a dictionary
    containing as key the log file name. The value of each key is given by a list of tuples in the form (malware,
    origin, parent). Both malware and parent are tuples of the form (malware_name, malware_pid).

    :param dir_results_path: path to the result folder
    :return: dictionary of corrupted processes by file name
    """
    corrupted_dict = {}
    file_path = dir_results_path + '/corrupted_processes.txt'

    if not os.path.isfile(file_path):
        logger.error('ERROR: corrupted_processes.txt file  not found')
        quit()

    with open(file_path, 'r', encoding='utf-8', errors='replace') as resfile:
        last_file_name = ''

        for line in resfile:
            if string_utils.filename in line:
                last_file_name = pandaloginvestigator.core.io.file_input.filename_from_analysis(line)
                corrupted_dict[last_file_name] = []
            elif line.strip():
                line = line.split('\t')
                malware = (line[2].strip(), line[3].strip())
                origin = line[4].strip()
                parent = (line[6].strip(), line[7].strip())
                corrupted_dict[last_file_name].append([malware, origin, parent])

    return corrupted_dict


def read_clues_regkey(dir_results_path: str) -> dict:
    """
    Reads the registry key clues output file in the specified folder. Buffers all the lines related to clues of a
    single log file into a list. Pass the list to the clue_object builder function. Generates a dictionary of clues
    having as key the log file name and as value the clue_object.

    :param dir_results_path: path to the result folder
    :return: dictionary of clue_objects by file name
    """
    clues_dict = {}
    clues_file_path = dir_results_path + '/clues_regkey.txt'

    if not os.path.isfile(clues_file_path):
        logger.error('WARNING: clues_regkey.txt file  not found')
        return clues_dict

    with open(clues_file_path, encoding='utf-8', errors='replace') as clues_file:
        last_file_name = ''
        lines = []
        for line in clues_file:
            if not line.strip():
                if len(lines) > 0:
                    new_clue = domain_utils.read_clue(last_file_name, lines)
                    clues_dict[last_file_name] = new_clue
                    last_file_name = ''
                    lines = []
            elif string_utils.filename in line:
                last_file_name = pandaloginvestigator.core.io.file_input.filename_from_analysis(line)
            else:
                lines.append(line)
    return clues_dict