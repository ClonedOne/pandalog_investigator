from pandaloginvestigator.core.utils import string_utils
import pprint
import ast

# ## OUTPUT UTILITY METHODS ##


# Output on file the analyzed content of one log file. For each malware object
# related to the specified file name it prints the content of each malware pid
# and sums up the executed instructions. The instruction count is divided into
# 4 separated parts: from_db, created, memory_written and total. Each of these
# counters consider only the instructions executed by pids whose origin
# corresponds to the specified one.
def output_on_file_instructions(filename, process_dict, inverted_process_dict, dir_analyzed_logs, db_file_malware_dict,                    file_corrupted_processes_dict, terminating_all, sleeping_all, crashing_all, error_all):

    with open(dir_analyzed_logs + '/' + filename, 'w', encoding='utf-8',
              errors='replace') as outfile:

        total_instructions = [0, 0, 0, 0]
        pprint.pprint(process_dict, outfile)
        outfile.write('\n')
        pprint.pprint(inverted_process_dict, outfile)
        outfile.write('\n')
        if filename in db_file_malware_dict:
            malware = db_file_malware_dict[filename]

            total_instructions = [sum(x) for x in
            zip(total_instructions,
            malware.get_total_executed_instructions())]

            outfile.write(str(malware) + '\n\n')
        if filename in file_corrupted_processes_dict:
            for malware in file_corrupted_processes_dict[filename]:

                total_instructions = [sum(x) for x in
                zip(total_instructions,
                malware.get_total_executed_instructions())]

                outfile.write(str(malware) + '\n\n')
        outfile.write(string_utils.instruction_final +
                      str(total_instructions) + '\n')

        outfile.write(string_utils.instruction_terminating +
                      str(terminating_all) + '\t' +
                      string_utils.instruction_sleeping +
                      str(sleeping_all) + '\t' +
                      string_utils.instruction_crashing +
                      str(crashing_all) + '\t' +
                      string_utils.instruction_raising_error +
                      str(error_all) + '\n')


# Similar to the previous but modified to output system call counting results.
def output_on_file_syscall(filename, dir_syscall_path, malware_syscall_dict, syscall_dict):

    with open(dir_syscall_path + '/' + filename, 'w', encoding='utf-8', errors='replace') as outfile:
        total_syscall = 0
        for system_call_num in sorted(list(syscall_dict)):
            system_call = syscall_dict[system_call_num]
            if system_call in malware_syscall_dict:
                total_syscall += malware_syscall_dict[system_call]
                outfile.write(system_call + ':\t' +
                              str(malware_syscall_dict[system_call]) + '\n')
        outfile.write('\n' + string_utils.syscall_final +
                      str(total_syscall))


# Prints the final output on file. The final output contains aggregate data
# regarding the totality of the analyzed logs. For each filename and each
# malware_object associated sums up the instruction for each pid, checks if
# each pid has been terminated and if each pid has called the sleep function.
def final_output_instructions(dir_results_path, filenames, db_file_malware_dict, file_corrupted_processes_dict, file_terminate_dict,file_sleep_dict, file_crash_dict, file_error_dict):

    with open(dir_results_path + '/' + 'analysis.txt', 'w', encoding='utf-8',
              errors='replace') as res_file:
        for filename in filenames:
            total_instructions = [0, 0, 0, 0]
            res_file.write(string_utils.filename + filename + '\n')
            if filename in db_file_malware_dict:
                entry = db_file_malware_dict[filename]

                total_instructions = [sum(x) for x in
                zip(total_instructions,
                entry.get_total_executed_instructions())]

            if filename in file_corrupted_processes_dict:
                for entry in file_corrupted_processes_dict[filename]:

                    total_instructions = [sum(x) for x in
                        zip(total_instructions,
                        entry.get_total_executed_instructions())]

            res_file.write(string_utils.instruction_final +
                           str(total_instructions) + '\n')
            res_file.write(string_utils.instruction_terminating +
                           (str(file_terminate_dict[filename]) if
                            filename in file_terminate_dict else str(False)) +
                           '\t')
            res_file.write(string_utils.instruction_sleeping +
                           (str(file_sleep_dict[filename]) if
                            filename in file_sleep_dict else str(False)) +
                           '\t')
            res_file.write(string_utils.crashing_all +
                           (str(file_crash_dict[filename]) if
                            filename in file_crash_dict else str(False)) +
                           '\t')
            res_file.write(string_utils.instruction_raising_error +
                           (str(file_error_dict[filename]) if
                            filename in file_error_dict else str(False)) +
                           '\n\n')


# Prints the final output on file. Modified for system call counting output.
def final_output_syscall(dir_results_path, filenames, filename_syscall_dict):
    with open(dir_results_path + '/syscalls.txt', 'w', encoding='utf-8',
              errors='replace') as res_file:
        for filename in filenames:
            total_syscall = 0
            res_file.write(string_utils.filename + filename + '\n')
            if filename in filename_syscall_dict:
                entry = filename_syscall_dict[filename]
                total_syscall = sum(entry.values())

            res_file.write(string_utils.syscall_final +
                           str(total_syscall))
            res_file.write('\n\n')


# Prints statistical information regarding the instruction analysis.
def output_instr_stats(dir_results_path, instr_totals_dict, inverted_totals, total_stats, terms, clean_stats, clean_instr_totals_dict):

    with open(dir_results_path + '/stats.txt', 'w', encoding='utf-8',
              errors='replace') as stats_file:
        stats_file.write('Filename <-> Total instruction count:\n\n')
        for f_name, tot in instr_totals_dict.items():
            stats_file.write(f_name + '\t' + str(tot) + '\n')
        stats_file.write('\n')
        stats_file.write('Total instruction count <-> Filename:\n\n')
        for key in sorted(inverted_totals.keys()):
            stats_file.write(str(key) + '\t' +
                             str(inverted_totals[key]) + '\n')
        stats_file.write('\n')
        stats_file.write(
            'Number of log files with non-null instruction count: \t' +
            str(len(instr_totals_dict)) + '\n')
        stats_file.write('Mean: \t' + str(total_stats[0]) + '\n')
        stats_file.write('Standard Deviation: \t' + str(total_stats[1]) + '\n')
        stats_file.write('Variance: \t' + str(total_stats[2]) + '\n\n')
        stats_file.write('Number of log files without crashes/errors: \t' +
                         str(len(clean_instr_totals_dict)) + '\n')
        stats_file.write('Mean without crashes/errors: \t' +
                         str(clean_stats[0]) + '\n')
        stats_file.write(
            'Standard Deviation without crashes/errors: \t' +
            str(clean_stats[1]) + '\n')
        stats_file.write('Variance without crashes/errors: \t' +
                         str(clean_stats[2]) + '\n\n')
        stats_file.write('Instruction count threshold: \t' +
                         str(total_stats[0] * 0.1) + '\n')
        stats_file.write(
            'Malwares below threshold: \t' + str(terms[0]) + '\n')
        stats_file.write(
            'Malwares below threshold terminating all processes:\t' +
            str(terms[1]) + '\n')
        stats_file.write(
            'Malwares below threshold sleeping all processes:\t' +
            str(terms[2]) + '\n')
        stats_file.write(
            'Malwares below threshold crashing all processes:\t' +
            str(terms[3]) + '\n')
        stats_file.write(
            'Malwares below threshold raising errors on all processes:\t' +
            str(terms[4]) + '\n')
        stats_file.write(
            'Malwares below threshold sleeping or terminating: \t' +
            str(terms[5]) + '\n')
        stats_file.write(
            'Malwares below threshold crashing or raising errors:\t' +
            str(terms[6]) + '\n\n')


# ## INPUT UTILITY METHODS ##


# Utility method to obtain the instruction count values from the relative line
# in the final analysis output text file.
def values_from_analysis(line):
    values = line.strip().split('\t')[1]
    values = values.translate({ord(c): None for c in '[],'}).split()
    return [int(val) for val in values]


# Utility method to obtain the file name value from the relative line
# in the final analysis output text file.
def filename_from_analysis(line):
    return line.split()[2].strip()


# Utility method to obtain the process status boolean flags from the relative
# line in the final analysis output text file.
def status_from_analysis(line):
    line = line.strip().split('\t')
    return [ast.literal_eval(line[1]),
            ast.literal_eval(line[3]),
            ast.literal_eval(line[5]),
            ast.literal_eval(line[7])]


# Utility method to obtain the system call count values from the relative line
# in the final analysis output text file.
def values_from_syscalls(line):
    return int(line.strip().split('\t')[1])
