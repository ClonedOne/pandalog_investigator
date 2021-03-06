import logging
import os

from pandaloginvestigator.core.io import file_input
from pandaloginvestigator.core.utils import string_utils

logger = logging.getLogger(__name__)


def read_result_corrupted(dir_results_path):
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

    with open(file_path, 'r', encoding='utf-8', errors='replace') as corrupted_file:
        last_file_name = ''

        for line in corrupted_file:
            if string_utils.filename in line:
                last_file_name = file_input.filename_from_analysis(line)
                corrupted_dict[last_file_name] = []
            elif line.strip():
                line = line.split('\t')
                malware = (line[2].strip(), line[3].strip())
                origin = line[4].strip()
                parent = (line[6].strip(), line[7].strip())
                corrupted_dict[last_file_name].append([malware, origin, parent])

    return corrupted_dict


def read_result_suspect(dir_results_path):
    """
    Reads and returns the dictionary of suspects from the result file. 
    
    :param dir_results_path: path to the results files directory
    :return: dictionary mapping suspect indices to samples uuid
    """
    suspects_dict = {}

    with open(os.path.join(dir_results_path, 'suspects.txt'), 'r', encoding='utf-8', errors='replace') as s_file:
        last_file_name = ''

        for line in s_file:
            if string_utils.filename in line:
                last_file_name = file_input.filename_from_analysis(line)
            elif string_utils.suspect_ind in line:
                index = float(line.split('\t')[1].strip())
                suspects_dict[last_file_name] = index

    return suspects_dict
