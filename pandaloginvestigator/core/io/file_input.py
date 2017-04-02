import ast

"""
    This file contains methods used to read partial and global results from file. 
"""


def values_from_analysis(line: str) -> list:
    """
    Utility method to obtain the instruction count values from the relative line in the final analysis output text
    file.

    :param line: string from log file
    :return: list of values
    """
    values = line.strip().split('\t')[1]
    values = values.translate({ord(c): None for c in '[],'}).split()
    return [int(val) for val in values]


def filename_from_analysis(line: str) -> str:
    """
    Utility method to obtain the file name value from the relative line in the final analysis output text file.

    :param line: string from log file
    :return: string containing file name
    """
    return line.split()[2].strip()


def status_from_analysis(line: str) -> list:
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


def values_from_syscalls(line: str) -> int:
    """
    Utility method to obtain the system call count values from the relative line in the final analysis output text
    file.

    :param line: string from log file
    :return: int corresponding to system call frequency
    """
    return int(line.strip().split('\t')[1])