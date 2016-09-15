from pandaloginvestigator.core.utils import pi_strings
from pandaloginvestigator.core.utils import utils
import matplotlib.pyplot as plt
import numpy
import ast
import logging


logger = logging.getLogger(__name__)

# Global variables declarations
no_instructions = pi_strings.no_instructions
totals_dict = {}
from_db_dict = {}
created_dict = {}
written_dict = {}
terminating_dict = {}
sleeping_dict = {}
crashing_dict = {}
error_dict = {}


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


def print_results(dir_results_path, inverted_totals, total_stats, terms, clean_stats, clean_totals_dict):
    with open(dir_results_path + '/stats.txt', 'w', codecs='utf-8', errors='replace') as stats_file:
        stats_file.write('Filename <-> Total instruction count:\n\n')
        for entry in totals_dict:
            stats_file.write(str(entry) + '\t' + str(totals_dict[entry]) + '\n')
        stats_file.write('\n')
        stats_file.write('Total instruction count <-> Filename:\n\n')
        for key in sorted(inverted_totals.keys()):
            stats_file.write(str(key) + '\t' + str(inverted_totals[key]) + '\n')
        stats_file.write('\n')
        stats_file.write('Number of log files with non-null instruction count: \t' + str(len(totals_dict)) + '\n')
        stats_file.write('Mean: \t' + str(total_stats[0]) + '\n')
        stats_file.write('Standard Deviation: \t' + str(total_stats[1]) + '\n')
        stats_file.write('Variance: \t' + str(total_stats[2]) + '\n\n')
        stats_file.write('Number of log files without crashes/errors: \t' + str(len(clean_totals_dict)) + '\n')
        stats_file.write('Mean without crashes/errors: \t' + str(clean_stats[0]) + '\n')
        stats_file.write('Standard Deviation without crashes/errors: \t' + str(clean_stats[1]) + '\n')
        stats_file.write('Variance without crashes/errors: \t' + str(clean_stats[2]) + '\n\n')
        stats_file.write('Instruction count threshold: \t' + str(total_stats[0] * 0.1) + '\n')
        stats_file.write('Number of malwares below threshold: \t' + str(terms[0]) + '\n')
        stats_file.write('Number of malwares below threshold terminating all processes: \t' + str(terms[1]) + '\n')
        stats_file.write('Number of malwares below threshold sleeping all processes: \t' + str(terms[2]) + '\n')
        stats_file.write('Number of malwares below threshold crashing all processes: \t' + str(terms[3]) + '\n')
        stats_file.write('Number of malwares below threshold raising errors on all processes: \t' + str(terms[4]) + '\n')
        stats_file.write('Number of malwares below threshold sleeping or terminating: \t' + str(terms[5]) + '\n')
        stats_file.write('Number of malwares below threshold crashing or raising errors: \t' + str(terms[6]) + '\n\n')


def accumulate_data(dir_results_path):
    next_file_name = True
    next_values = False
    next_term_sleep = False

    with open(dir_results_path + '/analysis.txt', 'r', codecs='utf-8', errors='replace') as resfile:
        last_file_name = ''
        for line in resfile:
            if not line.strip():
                next_file_name = True
                continue
            line = line.strip()
            if next_file_name:
                filename = line.split()[2]
                last_file_name = filename
                next_file_name = False
                next_values = True
                continue
            if next_values:
                if line != no_instructions:
                    values = line.split('\t')[1].replace('[', '').replace(']', '').replace(',', '').split()
                    from_db_dict[last_file_name] = int(values[0])
                    if int(values[1]) > 0:
                        created_dict[last_file_name] = int(values[1])
                    if int(values[2]) > 0:
                        written_dict[last_file_name] = int(values[2])
                    totals_dict[last_file_name] = int(values[3])
                next_values = False
                next_term_sleep = True
                continue
            if next_term_sleep:
                values = line.split('\t')
                terminating_dict[last_file_name] = ast.literal_eval(values[1].strip())
                sleeping_dict[last_file_name] = ast.literal_eval(values[3].strip())
                crashing_dict[last_file_name] = ast.literal_eval(values[5].strip())
                error_dict[last_file_name] = ast.literal_eval(values[7].strip())
                next_term_sleep = False


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

    return below_threshold, self_terminated, self_sleeping, self_crashing, self_raising_error, \
        sleep_or_terminate, crash_or_error


def prune_crashing_errors(dict_list, crashing_dict, error_dict):
    clean_dicts = []
    i = 0
    for cur_dict in dict_list:
        new_clean_dict = {}
        for filename in cur_dict:
            if not ((crashing_dict[filename]) or (error_dict[filename])):
                new_clean_dict[filename] = cur_dict[filename]
        clean_dicts.append(new_clean_dict)
        i += 1
    return clean_dicts


def plot_results(dir_results_path, target):
    accumulate_data(totals_dict,
                    from_db_dict,
                    created_dict,
                    written_dict,
                    terminating_dict,
                    sleeping_dict,
                    crashing_dict,
                    error_dict)
    inverted_totals = utils.invert_dictionary(totals_dict)
    clean_dicts = prune_crashing_errors([totals_dict, from_db_dict, created_dict, written_dict])
    clean_totals_dict = clean_dicts[0]
    clean_from_db_dict = clean_dicts[1]
    clean_created_dict = clean_dicts[2]
    clean_written_dict = clean_dicts[3]

    total_stats = utils.compute_stats(totals_dict)
    clean_total_stats = utils.compute_stats(clean_totals_dict)
    total_terms = compute_number_of_terminated(totals_dict, total_stats[0] * 0.1)
    print_results(inverted_totals, total_stats, total_terms, clean_total_stats, clean_totals_dict)

    do_stuff(totals_dict, 'b', 'H', 'Total')
    prune_data(totals_dict, 100)
    do_stuff(totals_dict, 'b', 'H', 'Total pruned')

    do_stuff(from_db_dict, 'g', 'o', 'Malware from database')
    prune_data(from_db_dict, 100)
    do_stuff(from_db_dict, 'g', 'o', 'Malware from database pruned')

    do_stuff(created_dict, 'r', 'o', 'Created processes')
    prune_data(created_dict, 10)
    do_stuff(created_dict, 'r', 'o', 'Created processes pruned')

    do_stuff(written_dict, 'y', 'o', 'Memory written processes')
    prune_data(written_dict, 10)
    do_stuff(written_dict, 'y', 'o', 'Memory written processes pruned')

    # Clean dictionaries
    do_stuff(clean_totals_dict, 'm', 'o', 'Total without crashes/errors')
    prune_data(clean_totals_dict, 100)
    do_stuff(clean_totals_dict, 'm', 'o', 'Total pruned without crashes/errors')

    do_stuff(clean_from_db_dict, 'g', 'o', 'Malware from database without crashes/errors')
    prune_data(clean_from_db_dict, 100)
    do_stuff(clean_from_db_dict, 'g', 'o', 'Malware from database pruned without crashes/errors')

    do_stuff(clean_created_dict, 'r', 'o', 'Created processes without crashes/errors')
    prune_data(clean_created_dict, 10)
    do_stuff(clean_created_dict, 'r', 'o', 'Created processes pruned without crashes/errors')

    do_stuff(clean_written_dict, 'y', 'o', 'Memory written processes without crashes/errors')
    prune_data(clean_written_dict, 10)
    do_stuff(clean_written_dict, 'y', 'o', 'Memory written processes pruned without crashes/errors')
