from collections import defaultdict
import logging
import os

logger = logging.getLogger(__name__)

"""
    General utility methods
"""


def strip_filename_ext(file_names):
    """
    Strip log file names from the extension.

    :param file_names: list of log file names as strings
    :return: list of log file names without the extension
    """
    return [filename[:-9] for filename in file_names]


def update_results(results, dict_list):
    """
    Given the results form the workers updates a list of dictionaries with the corresponding partial dictionaries
    contained in each of the worker sub result.

    :param results:
    :param dict_list:
    :return:
    """
    if len(results[0]) != len(dict_list):
        logger.error('Update Results length of partial result different from length of dict_list')
        quit()
    for sub_res in results:
        for i in range(len(sub_res)):
            dict_list[i].update(sub_res[i])


def merge_dict_dict(dict1, dict2):
    """
    Merge two dictionaries of dictionaries of int values into a new dictionary of dictionaries of int values where
    each value is the sum of the values in the original dictionaries (if available).

    :param dict1: Dictionary of dictionaries with int values
    :param dict2: Dictionary of dictionaries with int values
    :return: Dictionary of dictionaries with int values resulting from merge
    """
    dict_res = {}
    keys1 = list(dict1.keys())
    keys2 = list(dict2.keys())
    keys = set(keys1) | set(keys2)
    for key in keys:
        dict_res[key] = {}
        sub_dict1 = dict1.get(key, {})
        sub_dict2 = dict2.get(key, {})
        sub_keys1 = list(sub_dict1.keys())
        sub_keys2 = list(sub_dict2.keys())
        sub_keys = set(sub_keys1) | set(sub_keys2)
        for sub_key in sub_keys:
            val1 = sub_dict1.get(sub_key, 0)
            val2 = sub_dict2.get(sub_key, 0)
            val = val1 + val2
            dict_res[key][sub_key] = val
    return dict_res


def divide_workload(item_list, core_num, max_num=None):
    """
    Given a list of items and the number of CPU cores available, computes equal sized lists of items for each core. 
    'max_num' is a parameter bounding the maximum number of items to divide.

    :param item_list: list of items to split
    :param core_num: number of available CPU cores (workers)
    :param max_num: maximum number of elements to consider
    :return: defaultdict containing lists of elements divided equally
    """
    j = 0
    c = 0
    item_sublists = defaultdict(list)

    for item in item_list:
        item_sublists[j].append(item)
        j = (j + 1) % core_num
        c += 1
        if c == max_num:
            break
    if len(item_list) < core_num or max_num < core_num:
        while j < core_num:
            item_sublists[j] = []
            j += 1

    if len(item_sublists) != core_num:
        logger.error('size of split workload different from number of cores')
        quit()
    return item_sublists


def format_worker_input(core_num: int, item_sublists: defaultdict, fixed_params: tuple) -> list:
    """
    Generate a list of tuples containing the parameters to pass to worker sub processes.

    :param core_num: number of available cores
    :param item_sublists: dictionary containing the sublist of files for each worker
    :param fixed_params: list of parameters to be added to workers input
    :return: formatted list of worker input parameters
    """
    formatted_input = []
    for i in range(core_num):
        formatted_input.append((i, item_sublists[i]) + tuple(fixed_params))
    return formatted_input


def invert_dictionary(chosen_dict: dict) -> dict:
    """
    Given a dictionary returns the inverted dictionary, where each value is considered as a the new key.

    :param chosen_dict: dictionary of base types
    :return: dictionary containing reverse of passed dictionary
    """
    inverted_dict = {}
    for malware_name, count in chosen_dict.items():
        if count in inverted_dict:
            inverted_dict[count].append(malware_name)
        else:
            inverted_dict[count] = []
            inverted_dict[count].append(malware_name)
    return inverted_dict


def input_with_modifiers(dir_unpacked_path: str, dir_pandalogs_path: str, small_disk: bool = None,
                         max_num: object = None, file_list: list = None,
                         unpacking: bool = False) -> tuple:
    """
    Given the small_disk and max_num modifiers, returns the appropriate values for the max_num and filenames to be
    used by the workers.

    :param dir_unpacked_path:
    :param dir_pandalogs_path:
    :param small_disk:
    :param max_num:
    :param file_list:
    :param unpacking:
    :return:
    """
    filenames = []
    if file_list:
        logger.info('Input modifier: file_list')
        with open(file_list, 'r', encoding='utf-8', errors='replace') as list_file:
            for line in list_file:
                filenames.append(line.strip())
                filenames = sorted(filenames)
    elif small_disk:
        logger.info('Input modifier: small_disk')
        filenames = sorted(strip_filename_ext(os.listdir(dir_pandalogs_path)))
    elif unpacking:
        logger.info('Input modifier: unpacking')
        filenames = sorted(strip_filename_ext(os.listdir(dir_pandalogs_path)))
    else:
        filenames = sorted(os.listdir(dir_unpacked_path))
    if max_num:
        logger.info('Input modifier: max_num')
        max_num = int(max_num)
    else:
        max_num = len(filenames)
    return filenames, max_num
