import pprint
import os
import numpy


# ## DICTIONARY UTILITY METHODS ##

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
    for key, value in chosen_dict.iteritems():
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
    outfile = open(dir_analyzed_logs + filename + '_a.txt', 'w')
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


# Prints the final output on file. The final output contains aggregate data regarding the totality of the analyzed logs.
# For each filename and each malware_object associated sums up the instruction for each pid, checks if each pid
# has been terminated and if each pid has called the sleep function.
def final_output(dir_result_path, filenames, db_file_malware_dict, file_corrupted_processes_dict,
                 file_terminate_dict, file_sleep_dict, file_crash_dict, file_error_dict):
    with open(dir_result_path + '/' + 'analysis.txt', 'w', encoding='utf-8') as res_file:
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


# ## OTHER UTILITY METHODS ##

# Delete the temporary unpacked log file to avoid disk congestion.
def clean_log(filename, dir_unpacked_path):
    os.remove(dir_unpacked_path + '/' + filename)
