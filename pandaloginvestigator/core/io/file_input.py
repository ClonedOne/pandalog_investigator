from os import path
import jsonpickle
import ast

"""
This file contains methods used to read from application related files.
"""


def values_from_analysis(line):
    """
    Utility method to obtain the instruction count values from the relative line in the final analysis output text
    file.

    :param line: string from log file
    :return: list of values
    """
    values = line.strip().split('\t')[1]
    values = values.translate({ord(c): None for c in '[],'}).split()
    return [int(val) for val in values]


def filename_from_analysis(line):
    """
    Utility method to obtain the file name value from the relative line in the final analysis output text file.

    :param line: string from log file
    :return: string containing file name
    """
    return line.split()[2].strip()


def status_from_analysis(line):
    """
    Utility method to obtain the process status boolean flags from the relative line in the final analysis output
    text file.

    :param line: string from log file
    :return: list of boolean status flags
    """
    line = line.strip().split('\t')
    return [ast.literal_eval(line[1]),
            ast.literal_eval(line[3]),
            ast.literal_eval(line[5]),
            ast.literal_eval(line[7]),
            ast.literal_eval(line[9])]


def values_from_syscalls(line):
    """
    Utility method to obtain the system call count values from the relative line in the final analysis output text
    file.

    :param line: string from log file
    :return: int corresponding to system call frequency
    """
    return int(line.strip().split('\t')[1])


def get_registry_keys():
    """
    Utility method to obtain the list of dangerous registry keys and values from the included file.
    
    :return: dictionary containing registry keys and values lists. 
    """

    with open("registry_keys.json", "r", encoding='utf-8', errors='replace') as reg_file:
        registry_keys = jsonpickle.decode(reg_file.read())
    return registry_keys


def load_sample(sample_uuid, dir_analyzed):
    """
    Utility method to read a json file containing the Sample object representation and return it.
    
    :param sample_uuid: uuid of the sample
    :param dir_analyzed: path to the analyzed pandalog files
    :return: Sample object
    """

    with open(path.join(dir_analyzed, sample_uuid + '.json'), "r", encoding='utf-8', errors='replace') as sample_file:
        sample = jsonpickle.decode(sample_file.read())
    return sample
