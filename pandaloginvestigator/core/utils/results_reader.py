from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.utils import domain_utils
import logging
import os


logger = logging.getLogger(__name__)


# Wrapper used to provide the correct data to both plotter methods.
def read_data(dir_results_path, target):
    if target == string_utils.target_i:
        return read_result_instr(dir_results_path)
    elif target == string_utils.target_s:
        return read_result_syscall(dir_results_path)


# Read the instruction counting analysis result file in order to generate a
# dictionary containing the values from the file. This data will then be used
# in the statistics generation and plotting phase.
def read_result_instr(dir_results_path):
    instr_totals_dict = {}
    instr_from_db_dict = {}
    created_dict = {}
    written_dict = {}
    terminating_dict = {}
    sleeping_dict = {}
    crashing_dict = {}
    error_dict = {}
    file_path = dir_results_path + '/analysis.txt'
    with open(file_path, 'r', encoding='utf-8', errors='replace') as resfile:
        last_file_name = ''
        for line in resfile:
            if string_utils.filename in line:
                last_file_name = file_utils.filename_from_analysis(line)
            elif string_utils.instruction_final in line:
                if line != string_utils.no_instructions:
                    values = file_utils.values_from_analysis(line)
                    instr_from_db_dict[last_file_name] = int(values[0])
                    if int(values[1]) > 0:
                        created_dict[last_file_name] = int(values[1])
                    if int(values[2]) > 0:
                        written_dict[last_file_name] = int(values[2])
                    instr_totals_dict[last_file_name] = int(values[3])
            elif string_utils.instruction_terminating in line:
                status = file_utils.status_from_analysis(line)
                terminating_dict[last_file_name] = status[0]
                sleeping_dict[last_file_name] = status[1]
                crashing_dict[last_file_name] = status[2]
                error_dict[last_file_name] = status[3]
    return [
        instr_totals_dict,
        instr_from_db_dict,
        created_dict,
        written_dict,
        terminating_dict,
        sleeping_dict,
        crashing_dict,
        error_dict
    ]


# Read the system call counting result file in order to generate a dictionary
# containing the values from the file. This data will then be used in the
# statistics generation and plotting phase.
def read_result_syscall(dir_results_path):
    syscalls_totals_dict = {}
    file_path = dir_results_path + '/syscalls.txt'
    with open(file_path, 'r', encoding='utf-8', errors='replace') as resfile:
        last_file_name = ''
        for line in resfile:
            if string_utils.filename in line:
                last_file_name = file_utils.filename_from_analysis(line)
            elif string_utils.syscall_final in line:
                if line != string_utils.no_syscalls:
                    value = file_utils.values_from_syscalls(line)
                    syscalls_totals_dict[last_file_name] = value
    return [syscalls_totals_dict, ]


# Read the corrupted processes list and return a dictionary containing
# as key the log file name and as value the structure of related processes.
def read_result_corrupted(dir_results_path):
    corrupted_dict = {}
    file_path = dir_results_path + '/corrupted_processes.txt'

    if not os.path.isfile(file_path):
        logger.error('ERROR: corrupted_processes.txt file  not found')
        quit()

    with open(file_path, 'r', encoding='utf-8', errors='replace') as resfile:
        last_file_name = ''

        for line in resfile:
            if string_utils.filename in line:
                last_file_name = file_utils.filename_from_analysis(line)
                corrupted_dict[last_file_name] = []
            elif line.strip():
                line = line.split('\t')
                malware = (line[2].strip(), line[3].strip())
                origin = line[4].strip()
                parent = (line[6].strip(), line[7].strip())
                corrupted_dict[last_file_name].append([malware, origin, parent])

    return corrupted_dict


# Read the registry key clues output file and generate a dictionary of clues
# def read_clues_regkey(dir_results_path):
#     clues_dict = {}
#     clues_file_path = dir_results_path + '/clues_regkey.txt'
#
#     if not os.path.isfile(clues_file_path):
#         logger.error('WARNING: clues_regkey.txt file  not found')
#         return clues_dict
#
#     with open(clues_file_path, encoding='utf-8', errors='replace') as clues_file:
#         last_file_name = ''
#         for line in clues_file:
#             if string_utils.filename in line:
#                 last_file_name = file_utils.filename_from_analysis(line)
#                 clues_dict[last_file_name] = {}
#             else:
#                 if not line.strip():
#                     pass
#                 else:
#                     values = file_utils.values_from_clues_regkey(line)
#                     counter = int(values[2])
#                     proc_name = values[4]
#                     proc_id = values[5]
#                     process = (proc_name, proc_id)
#                     if process in clues_dict.get(last_file_name, {}):
#                         clues_dict[last_file_name][process] += counter
#                     else:
#                         clues_dict[last_file_name][process] = counter
#     return clues_dict


def read_clues_regkey(dir_results_path):
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
                last_file_name = file_utils.filename_from_analysis(line)
            else:
                lines.append(line)

    return clues_dict