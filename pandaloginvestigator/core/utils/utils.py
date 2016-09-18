from collections import defaultdict
import os
import numpy


# ## STATISTICAL UTILITY METHODS ##

# Compute statistical information about the specified dictionary.
# Returns mean, standard deviation and variance of the values contained.
def compute_stats(chosen_dict):
    values = numpy.array(list(chosen_dict.values()))
    mean = values.mean()
    standard_deviation = values.std()
    variance = values.var()
    return mean, standard_deviation, variance


# Delete the highest and lowest (key, value) pairs from a dictionary,
# ordered by value.
def prune_data(chosen_dict, threshold_number):
    pruned_dict = {}
    values = sorted(chosen_dict.values())
    values = values[threshold_number : -threshold_number]
    for filename, value in chosen_dict.items():
        if value in values:
            pruned_dict[filename] = value
    return pruned_dict


# Delete values from a dictionary if their keys are contained in the specified dictionaries.
def prune_crashing_errors(dict_list, crashing_dict, error_dict):
    print(crashing_dict)
    print(error_dict)
    clean_dicts = []
    i = 0
    for cur_dict in dict_list:
        new_clean_dict = {}
        for filename in cur_dict:
            if not (crashing_dict.get(filename, False)) and not(error_dict.get(filename, False)):
                new_clean_dict[filename] = cur_dict[filename]
        clean_dicts.append(new_clean_dict)
        i += 1
    return clean_dicts


# ## OTHER UTILITY METHODS ##

# Delete the temporary unpacked log file to avoid disk congestion.
def clean_log(filename, dir_unpacked_path):
    os.remove(dir_unpacked_path + '/' + filename)


# Given the results form the workers updates a list of dictionaries with
# the corresponding partial dictionaries contained in each of
# the worker sub result.
def update_results(results, dict_list):
    if len(results[0]) != len(dict_list):
        return -1
    for sub_res in results:
        for i in range(len(sub_res)):
            dict_list[i].update(sub_res[i])
    return 1


# Given a list of items and the number of processing cores available compute
# a list of items lists of equal dimension, one for each core.
# 'max_num' is a parameter bounding the maximum number of items to divide.
def divide_workload(item_list, core_num, max_num):
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
