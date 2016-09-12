import pprint
import subprocess
import os
import numpy


# Compute statistical information about the specified dectionary
def compute_stats(chosen_dict):
    values = numpy.array(chosen_dict.values())
    mean = values.mean()
    standard_deviation = values.std()
    variance = values.var()
    return mean, standard_deviation, variance


# Unpack the specified log file using the PANDA 'pandalog_reader' utility.
# The content of the log will be saved in a temporary file with the same name.
def unpack_log(filename, dir_pandalogs_path, dir_unpacked_path):
    unpack_command = './pandalog_reader'
    reduced_filename = filename[:-9]
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + reduced_filename, shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


# Handles the acquisition of the path string from the log file.
# It is used to handle linux problems with windows style path strings.
def get_new_path(path_input):
    words = path_input.split()
    line = ''
    fixed = 'name=['
    for word in words:
        line += word + ' '
    index = line.find(fixed)
    line = line[index:]
    return os.path.normpath(line.split('[')[1].replace(']', ''))


# Output on file the analyzed content of one log file.
# For each malware object related to the specified file name it prints the content fo each malware pid and
# sums up the executed instructions. The isntruction count is divided into 4 separated parts: from_db, created,
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


# Delete the temporary unpacked log file to avoid disk congestion.
def clean_log(filename, dir_unpacked_path):
    os.remove(dir_unpacked_path + filename + '.txt')


# Prints the final output on file. The final output contains aggregate data regarding the totality of the analyzed logs.
# For each filename and each malware_object associated sums up the instruction for each pid, checks if each pid
# has been terminated and if each pid has called the sleep function.
def final_output(dir_project_path, filenames, db_file_malware_dict, file_corrupted_processes_dict,
                 file_terminate_dict, file_sleep_dict, file_crash_dict, file_error_dict):
    res_file = open(dir_project_path + 'resfile.txt', 'w')
    for filename in filenames:
        filename = filename[:-9]
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
        res_file.write('Final instruction count: \t' + str(total_instruction_accumulator))
        res_file.write('\nTerminating all: \t' + (str(file_terminate_dict[filename])
                                                  if filename in file_terminate_dict else str(False)))
        res_file.write('\tSleeping all: \t' + (str(file_sleep_dict[filename])
                                               if filename in file_sleep_dict else str(False)))
        res_file.write('\tCrashing all: \t' + (str(file_crash_dict[filename])
                                               if filename in file_crash_dict else str(False)))
        res_file.write('\tRaising hard error all: \t' + (str(file_error_dict[filename])
                                                         if filename in file_error_dict else str(False)))
        res_file.write('\n\n')


# Updates the pid - process dictionaries with new a new process and pid at each context switch.
def update_dictionaries(pid, process_dict, proc_name, inverted_process_dict):
    if pid in process_dict:
        if proc_name in process_dict[pid]:
            process_dict[pid][proc_name] += 1
        else:
            process_dict[pid][proc_name] = 1
    else:
        process_dict[pid] = {}
        process_dict[pid][proc_name] = 1

    # the same values will also be added to the inverted dictionary
    if proc_name in inverted_process_dict:
        if pid in inverted_process_dict[proc_name]:
            inverted_process_dict[proc_name][pid] += 1
        else:
            inverted_process_dict[proc_name][pid] = 1
    else:
        inverted_process_dict[proc_name] = {}
        inverted_process_dict[proc_name][pid] = 1


# Delete the highest and lowest values from a dictionary
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
