from collections import defaultdict
import pprint
import os
import numpy


# ## STATISTICAL UTILITY METHODS ##

# Compute statistical information about the specified dictionary.
# Returns mean, standard deviation and variance of the values contained.
def compute_stats(chosen_dict):
    values = numpy.array(chosen_dict.values())
    mean = values.mean()
    standard_deviation = values.std()
    variance = values.var()
    return mean, standard_deviation, variance


# Delete the highest and lowest (key, value) pairs from a dictionary,
# ordered by value.
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


# ## OUTPUT UTILITY METHODS ##

# Output on file the analyzed content of one log file.
# For each malware object related to the specified file name it prints the content of each malware pid and
# sums up the executed instructions. The instruction count is divided into 4 separated parts: from_db, created,
# memory_written and total. Each of these counters consider only the instructions executed by pids whose origin
# corresponds to the specified one.
def output_on_file(filename, process_dict, inverted_process_dict, dir_analyzed_logs,
                   db_file_malware_dict, file_corrupted_processes_dict,
                   terminating_all, sleeping_all, crashing_all, error_all):
    with open(dir_analyzed_logs + '/' + filename, 'w', encoding='utf-8', errors='replace') as outfile:
        total_instruction_accumulator = [0, 0, 0, 0]
        pprint.pprint(process_dict, outfile)
        outfile.write('\n')
        pprint.pprint(inverted_process_dict, outfile)
        outfile.write('\n')
        if filename in db_file_malware_dict:
            malware = db_file_malware_dict[filename]
            total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                 malware.get_total_executed_instructions())]
            outfile.write(str(malware) + '\n\n')
        if filename in file_corrupted_processes_dict:
            for malware in file_corrupted_processes_dict[filename]:
                total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                     malware.get_total_executed_instructions())]
                outfile.write(str(malware) + '\n\n')
        outfile.write('\nFinal instruction count: \n' + str(total_instruction_accumulator))
        outfile.write('\nTerminating all: \t' + str(terminating_all) + '\tSleeping all: \t' + str(sleeping_all) +
                      '\t Crashing all: \t' + str(crashing_all) + '\t Raising hard error all: \t' + str(error_all))


# Similar to the previous but modified to output system call counting results.
def output_on_file_syscall(filename, dir_syscall_path, malware_syscall_dict, syscall_dict):
    with open(dir_syscall_path + '/' + filename, 'w', encoding='utf-8', errors='replace') as outfile:
        total_syscall_accumulator = 0
        for system_call_num in sorted(list(syscall_dict)):
            system_call = syscall_dict[system_call_num]
            if system_call in malware_syscall_dict:
                total_syscall_accumulator += malware_syscall_dict[system_call]
                outfile.write(system_call + ':\t' + str(malware_syscall_dict[system_call]) + '\n')
        outfile.write('\nFinal system call count: \t' + str(total_syscall_accumulator))


# Prints the final output on file. The final output contains aggregate data regarding the totality of the analyzed logs.
# For each filename and each malware_object associated sums up the instruction for each pid, checks if each pid
# has been terminated and if each pid has called the sleep function.
def final_output(dir_results_path, filenames, db_file_malware_dict, file_corrupted_processes_dict,
                 file_terminate_dict, file_sleep_dict, file_crash_dict, file_error_dict):
    with open(dir_results_path + '/' + 'analysis.txt', 'w', encoding='utf-8', errors='replace') as res_file:
        for filename in filenames:
            total_instruction_accumulator = [0, 0, 0, 0]
            res_file.write('File name: ' + filename + '\n')
            if filename in db_file_malware_dict:
                entry = db_file_malware_dict[filename]
                total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                     entry.get_total_executed_instructions())]
            if filename in file_corrupted_processes_dict:
                for entry in file_corrupted_processes_dict[filename]:
                    total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                         entry.get_total_executed_instructions())]
            res_file.write('Final instruction count: \t' +
                           str(total_instruction_accumulator))
            res_file.write('\nTerminating all: \t' +
                           (str(file_terminate_dict[filename]) if filename in file_terminate_dict else str(False)))
            res_file.write('\tSleeping all: \t' +
                           (str(file_sleep_dict[filename]) if filename in file_sleep_dict else str(False)))
            res_file.write('\tCrashing all: \t' +
                           (str(file_crash_dict[filename]) if filename in file_crash_dict else str(False)))
            res_file.write('\tRaising hard error all: \t' +
                           (str(file_error_dict[filename]) if filename in file_error_dict else str(False)))
            res_file.write('\n\n')


# Prints the final output on file. Modified for system call counting output.
def final_output_syscall(dir_results_path, filenames, filename_syscall_dict):
    with open(dir_results_path + '/' + 'syscalls.txt', 'w', encoding='utf-8', errors='replace') as res_file:
        for filename in filenames:
            total_syscall_accumulator = 0
            res_file.write('File name: ' + filename + '\n')
            if filename in filename_syscall_dict:
                entry = filename_syscall_dict[filename]
                total_syscall_accumulator = sum(entry.values())

            res_file.write('Final instruction count: \t' +
                           str(total_syscall_accumulator))
            res_file.write('\n\n')


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


# Generate a list of tuples containing the parameters to pass to worker subprocesses.
def format_worker_input(core_num, item_sublists, fixed_params_list):
    formatted_input = []
    for i in range(core_num):
        formatted_input.append((i, item_sublists[i]) + tuple(fixed_params_list))
    return formatted_input


# Given a dictionary returns the inverted dictionary, where each value is considered
# as a the new key.
def invert_dictionary(chosen_dict):
    inverted_dict = {}
    for malware_name, count in chosen_dict.iteritems():
        if count in inverted_dict:
            inverted_dict[count].append(malware_name)
        else:
            inverted_dict[count] = []
            inverted_dict[count].append(malware_name)
    return inverted_dict
