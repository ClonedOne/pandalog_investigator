import logging

import matplotlib.pyplot as plt
import numpy
from pandaloginvestigator.core.utils import results_reader
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils

logger = logging.getLogger(__name__)


def plot_results(dir_results_path, target):
    dict_list = results_reader.read_data(dir_results_path, target)
    if target == string_utils.target_i:
        inverted_totals = utils.invert_dictionary(dict_list[0])
        to_clean = [dict_list[i] for i in range(4)]
        clean_dicts = utils.prune_crashing_errors(to_clean, dict_list[6], dict_list[7])
        plot_instruction_results(dict_list, clean_dicts)
    elif target == string_utils.target_s:
        plot_syscall_results(dict_list)
        return


# Plot the graphs related to instruction analysis.
def plot_instruction_results(dict_list, clean_dicts):
    do_stuff(dict_list[0], 'b', 'H', 'Total', 100, True)
    do_stuff(dict_list[1], 'g', 'o', 'Malware from database', 100, True)
    do_stuff(dict_list[2], 'r', 'o', 'Created processes', 10, True)
    do_stuff(dict_list[3], 'y', 'o', 'Memory written processes', 10, True)
    do_stuff(clean_dicts[0], 'm', 'o', 'Total without crashes/errors', 100, True)
    do_stuff(clean_dicts[1], 'g', 'o', 'Malware from database without crashes/errors', 100, True)
    do_stuff(clean_dicts[2], 'r', 'o', 'Created processes without crashes/errors', 10, True)
    do_stuff(clean_dicts[3], 'y', 'o', 'Memory written processes without crashes/errors', 10, True)


def plot_syscall_results(dict_list):
    do_stuff(dict_list[0], 'b', 'H', 'Total system calls', 100, True)


# Auxiliary method for generating statistics, pruning values and plotting.
def do_stuff(chosen_dict, color, shape, title, prune, hist=None):
    stats = utils.compute_stats(chosen_dict)
    plot_data(chosen_dict, stats, color, shape, title, hist)
    chosen_dict_pruned = utils.prune_data(chosen_dict, prune)
    stats = utils.compute_stats(chosen_dict_pruned)
    plot_data(chosen_dict_pruned, stats, color, shape, title + ' pruned', hist)


# Plot the data contained in the specified dictionary.
def plot_data(chosen_dict, stats, color, shape, title, hist=None):
    accumulation_list = []
    ranges = []
    standard_deviation = stats[1]
    std_multiplier = 0.0
    i = 0
    values = numpy.array(sorted(list(chosen_dict.values())))
    if hist:
        plt.hist(values,  color=color)
    else:
        for value in values:
            while value >= standard_deviation * std_multiplier:
                accumulation_list.append(0)
                std_multiplier += 0.1
                ranges.append(standard_deviation * std_multiplier)
                i += 1
            accumulation_list[i - 1] += 1
        accumulation_list = numpy.array(accumulation_list)
        ranges = numpy.array(ranges)
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.plot(ranges, accumulation_list, color + shape, markersize=8)
        ax.plot(ranges, accumulation_list, color, linewidth=2)
    plt.title(title)
    plt.xlabel("Value range")
    plt.ylabel("Frequency")
    plt.show()
