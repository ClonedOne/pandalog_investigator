from collections import defaultdict
import os
import logging


logger = logging.getLogger(__name__)


# ## OTHER UTILITY METHODS ##

def strip_filename_ext(filenames):
    """
    Strip log file names from the extension.
    :param filenames:
    :return: string filename without extension
    """
    return [filename[:-9] for filename in filenames]


def update_results(results, dict_list):
    """
    Given the results form the workers updates a list of dictionaries with
    the corresponding partial dictionaries contained in each of
    the worker sub result.
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
    Merge two dictionaries of dictionaries  of int values into
    a new dictionary of dictionaries of int values where each
    value is the sum of the values in the original dictionaries.
    :param dict1:
    :param dict2:
    :return: dict
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
    Given a list of items and the number of processing cores available compute
    a list of items lists of equal dimension, one for each core.
    'max_num' is a parameter bounding the maximum number of items to divide.
    :param item_list:
    :param core_num:
    :param max_num:
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
    if len(item_sublists) < core_num:
        while j != 0:
            item_sublists[j] = []
            j = (j + 1) % core_num

    if len(item_sublists) != core_num:
        logger.error('size of split workload different from number of cores')
        quit()
    return item_sublists


def format_worker_input(core_num, item_sublists, fixed_params_list):
    """
    Generate a list of tuples containing the parameters to pass to worker
    sub processes.
    :param core_num:
    :param item_sublists:
    :param fixed_params_list:
    :return: list of input formatted accordingly to worker modules specs
    """
    formatted_input = []
    for i in range(core_num):
        formatted_input.append(
            (i, item_sublists[i]) + tuple(fixed_params_list))
    return formatted_input


def invert_dictionary(chosen_dict):
    """
    Given a dictionary returns the inverted dictionary, where each value is
    considered as a the new key.
    :param chosen_dict:
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
