from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils
from pandaloginvestigator.core.utils import file_utils
import matplotlib.pyplot as plt
import numpy
import logging


logger = logging.getLogger(__name__)

# Global variables declarations
instr_totals_dict = {}
instr_from_db_dict = {}
created_dict = {}
written_dict = {}
terminating_dict = {}
sleeping_dict = {}
crashing_dict = {}
error_dict = {}
syscalls_totals_dict = {}

target_i = 'instructions'
target_s = 'syscalls'


# Plot the data contained in the specified dictionary.
def plot_data(chosen_dict, stats, color, shape, title):
    accumulation_list = []
    ranges = []
    standard_deviation = stats[1]
    std_multiplier = 0.0
    i = 0
    values = numpy.array(sorted(chosen_dict.values()))
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


# Read the instruction counting analysis result file in order to generate a
# dictionary containing the values from the file. This data will then be used
# in the statistics generation and plotting phase.
def read_result_instr(dir_results_path):
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


# Read the system call counting result file in order to generate a dictionary
# containing the values from the file. This data will then be used in the
# statistics generation and plotting phase.
def read_result_syscall(dir_results_path):
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


def prune_data(chosen_dict, threshold_number):
    values = sorted(chosen_dict.values())
    length = len(values)
    eliminate_vals = []
    eliminate_keys = []
    for i in range(length):
        if i < threshold_number or (length - 1) - i < threshold_number:
            eliminate_vals.append(values[i])
    for key, value in chosen_dict.items():
        if value in eliminate_vals:
            eliminate_keys.append(key)
    for key in eliminate_keys:
        chosen_dict.pop(key)


def do_stuff(chosen_dict, color, shape, title, log=False):
    stats = utils.compute_stats(chosen_dict)
    plot_data(chosen_dict, stats, color, shape, title, log)


def compute_number_of_terminated(chosen_dict, threshold):
    below_threshold = 0
    self_terminated = 0
    self_sleeping = 0
    self_crashing = 0
    self_raising_error = 0
    crash_or_error = 0
    sleep_or_terminate = 0
    for filename, value in chosen_dict.items():
        if value < threshold:
            below_threshold += 1
            if terminating_dict[filename]:
                self_terminated += 1
            if sleeping_dict[filename]:
                self_sleeping += 1
            if sleeping_dict[filename] or terminating_dict[filename]:
                sleep_or_terminate += 1
            if crashing_dict[filename]:
                self_crashing += 1
            if error_dict[filename]:
                self_raising_error += 1
            if crashing_dict[filename] or error_dict[filename]:
                crash_or_error += 1

    return below_threshold, self_terminated, self_sleeping, self_crashing,
    self_raising_error, sleep_or_terminate, crash_or_error


def prune_crashing_errors(dict_list, crashing_dict, error_dict):
    clean_dicts = []
    i = 0
    for cur_dict in dict_list:
        new_clean_dict = {}
        for filename in cur_dict:
            if filename not in crashing_dict and filename not in error_dict:
                new_clean_dict[filename] = cur_dict[filename]
        clean_dicts.append(new_clean_dict)
        i += 1
    return clean_dicts


def plot_results(dir_results_path, target):
    read_data(dir_results_path, target)
    if target == target_i:
        inverted_totals = utils.invert_dictionary(instr_totals_dict)
        clean_dicts = prune_crashing_errors(instr_from_db_dict,
                                            created_dict, written_dict)
        total_stats = utils.compute_stats(instr_totals_dict)
        clean_total_stats = utils.compute_stats(clean_dicts[0])
        total_terms = compute_number_of_terminated(instr_totals_dict,
                                                   total_stats[0] * 0.1)
        file_utils.output_instr_stats(
            inverted_totals,
            total_stats,
            total_terms,
            clean_total_stats,
            clean_dicts[0]
        )
        plot_instruction_results(clean_dicts)


# Plot the graphs related to system calls analysis.
def plot_syscalls_results(dir_results_path):
    # total_dict = gather_data()
    # total_stats = utils.compute_stats(total_dict)
    # reduced_dict = gather_data(False)
    # reduced_stats = utils.compute_stats(reduced_dict)
    # plot_data(total_dict, total_stats, 'b', 'o', 'Total system calls')
    # plot_data(reduced_dict, reduced_stats, 'g',
    #           'o', 'System calls excluding waiting')

    # utils.prune_data(total_dict, 200)
    # total_stats_pruned = utils.compute_stats(total_dict)
    # utils.prune_data(reduced_dict, 2100)
    # reduced_stats_pruned = utils.compute_stats(reduced_dict)
    # plot_data(total_dict, total_stats_pruned, 'b',
    #           'o', 'Total system calls pruned')
    # plot_data(reduced_dict, reduced_stats_pruned, 'g',
    #           'o', 'System calls excluding waiting pruned')
    return


# Wrapper used to provide the correct data to both plotter methods.
def read_data(dir_results_path, target):
    if target == target_i:
        read_result_instr(dir_results_path)
    elif target == target_s:
        read_result_syscall(dir_results_path)


# Plot the graphs related to instruction analysis.
def plot_instruction_results(clean_dicts):
    clean_instr_totals_dict = clean_dicts[0]
    clean_instr_from_db_dict = clean_dicts[1]
    clean_created_dict = clean_dicts[2]
    clean_written_dict = clean_dicts[3]

    do_stuff(instr_totals_dict, 'b', 'H', 'Total')
    prune_data(instr_totals_dict, 100)
    do_stuff(instr_totals_dict, 'b', 'H', 'Total pruned')

    do_stuff(instr_from_db_dict, 'g', 'o', 'Malware from database')
    prune_data(instr_from_db_dict, 100)
    do_stuff(instr_from_db_dict, 'g', 'o', 'Malware from database pruned')

    do_stuff(created_dict, 'r', 'o', 'Created processes')
    prune_data(created_dict, 10)
    do_stuff(created_dict, 'r', 'o', 'Created processes pruned')

    do_stuff(written_dict, 'y', 'o', 'Memory written processes')
    prune_data(written_dict, 10)
    do_stuff(written_dict, 'y', 'o', 'Memory written processes pruned')

    # Clean dictionaries
    do_stuff(clean_instr_totals_dict, 'm', 'o', 'Total without crashes/errors')
    prune_data(clean_instr_totals_dict, 100)
    do_stuff(clean_instr_totals_dict, 'm', 'o',
             'Total pruned without crashes/errors')

    do_stuff(clean_instr_from_db_dict, 'g', 'o',
             'Malware from database without crashes/errors')
    prune_data(clean_instr_from_db_dict, 100)
    do_stuff(clean_instr_from_db_dict, 'g', 'o',
             'Malware from database pruned without crashes/errors')

    do_stuff(clean_created_dict, 'r', 'o',
             'Created processes without crashes/errors')
    prune_data(clean_created_dict, 10)
    do_stuff(clean_created_dict, 'r', 'o',
             'Created processes pruned without crashes/errors')

    do_stuff(clean_written_dict, 'y', 'o',
             'Memory written processes without crashes/errors')
    prune_data(clean_written_dict, 10)
    do_stuff(clean_written_dict, 'y', 'o',
             'Memory written processes pruned without crashes/errors')
