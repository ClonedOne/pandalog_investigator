from collections import defaultdict
import os
import logging


logger = logging.getLogger(__name__)


# ## OTHER UTILITY METHODS ##

# Delete the temporary unpacked log file to avoid disk congestion.
def clean_log(filename, dir_unpacked_path):
    os.remove(dir_unpacked_path + '/' + filename)


# Given the results form the workers updates a list of dictionaries with
# the corresponding partial dictionaries contained in each of
# the worker sub result.
def update_results(results, dict_list):
    if len(results[0]) != len(dict_list):
        logger.error('Update Results length of partial result different from length of dict_list')
        return -1
    for sub_res in results:
        for i in range(len(sub_res)):
            dict_list[i].update(sub_res[i])
    return 1


# Given a list of items and the number of processing cores available compute
# a list of items lists of equal dimension, one for each core.
# 'max_num' is a parameter bounding the maximum number of items to divide.
def divide_workload(item_list, core_num, max_num=None):
    j = 0
    c = 0
    item_sublists = defaultdict(list)
    for item in item_list:
        item_sublists[j].append(item)
        j = (j + 1) % core_num
        c += 1
        if c == max_num:
            break
    return item_sublists


# Generate a list of tuples containing the parameters to pass to worker
# subprocesses.
def format_worker_input(core_num, item_sublists, fixed_params_list):
    formatted_input = []
    for i in range(core_num):
        formatted_input.append(
            (i, item_sublists[i]) + tuple(fixed_params_list))
    return formatted_input


# Given a dictionary returns the inverted dictionary, where each value is
# considered as a the new key.
def invert_dictionary(chosen_dict):
    inverted_dict = {}
    for malware_name, count in chosen_dict.items():
        if count in inverted_dict:
            inverted_dict[count].append(malware_name)
        else:
            inverted_dict[count] = []
            inverted_dict[count].append(malware_name)
    return inverted_dict
