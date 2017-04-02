from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import string_utils
from os import path
import jsonpickle


"""
    This file contains methods used to output partial and global results on file. 
"""


def output_on_file_syscall(filename, dir_syscall_path, malware_syscall_dict, syscall_dict):
    """
    Similar to the previous but modified to output system call counting results.

    :param filename:
    :param dir_syscall_path:
    :param malware_syscall_dict:
    :param syscall_dict:
    :return:
    """
    with open(dir_syscall_path + '/' + filename, 'w', encoding='utf-8', errors='replace') as outfile:
        total_syscall = 0

        for system_call_num in sorted(list(syscall_dict)):
            system_call = syscall_dict[system_call_num]
            if system_call in malware_syscall_dict:
                total_syscall += malware_syscall_dict[system_call]
                outfile.write(system_call + ':\t' +
                              str(malware_syscall_dict[system_call]) + '\n')

        outfile.write('{} {}\n'.format(string_utils.syscall_final, total_syscall))


def final_output_instructions(dir_results_path, filenames, db_file_malware_dict, file_corrupted_processes_dict,
                              file_terminate_dict, file_sleep_dict, file_crash_dict, file_error_dict,
                              file_writefile_dict):
    """
    Prints the final output on file. The final output contains aggregate data regarding the totality of the analyzed
    logs. For each filename and each malware_object associated sums up the instruction for each pid, checks if each
    pid has been terminated and if each pid has called the sleep function.

    :param dir_results_path: path to the result folder
    :param filenames:
    :param db_file_malware_dict:
    :param file_corrupted_processes_dict:
    :param file_terminate_dict:
    :param file_sleep_dict:
    :param file_crash_dict:
    :param file_error_dict:
    :param file_writefile_dict:
    :return:
    """
    with open(dir_results_path + '/corrupted_processes.txt', 'w', encoding='utf-8', errors='replace') as cp_file:
        with open(dir_results_path + '/analysis.txt', 'w', encoding='utf-8', errors='replace') as res_file:
            for filename in filenames:
                total_instructions = [0, 0, 0, 0]

                res_file.write('{} {}\n'.format(string_utils.filename, filename))
                cp_file.write('{} {}\n'.format(string_utils.filename, filename))

                if filename in db_file_malware_dict:
                    entry = db_file_malware_dict[filename]
                    total_instructions = [sum(x) for x in
                                          zip(total_instructions, entry.get_total_executed_instructions())]
                    cp_file.write(domain_utils.repr_malware_processes(entry))

                if filename in file_corrupted_processes_dict:
                    for entry in file_corrupted_processes_dict[filename]:
                        total_instructions = [sum(x) for x in
                                              zip(total_instructions, entry.get_total_executed_instructions())]
                        cp_file.write(domain_utils.repr_malware_processes(entry))

                res_file.write(
                    string_utils.instruction_final + '\t' +
                    str(total_instructions) + '\n'
                )
                res_file.write(
                    string_utils.instruction_terminating + '\t' +
                    (str(file_terminate_dict[filename]) if filename in file_terminate_dict else str(False)) +
                    '\t'
                )
                res_file.write(
                    string_utils.instruction_sleeping + '\t' +
                    (str(file_sleep_dict[filename]) if filename in file_sleep_dict else str(False)) +
                    '\t'
                )
                res_file.write(
                    string_utils.instruction_crashing + '\t' +
                    (str(file_crash_dict[filename]) if filename in file_crash_dict else str(False)) +
                    '\t'
                )
                res_file.write(
                    string_utils.instruction_raising_error + '\t' +
                    (str(file_error_dict[filename]) if filename in file_error_dict else str(False)) +
                    '\t'
                )
                res_file.write(
                    string_utils.instruction_writes_file + '\t' +
                    (str(file_writefile_dict[filename]) if filename in file_writefile_dict else str(False)) +
                    '\n\n'
                )
                cp_file.write('\n\n')


def final_output_syscall(dir_results_path, filenames, filename_syscall_dict):
    """
    Prints the final output on file. Modified for system call counting output.

    :param dir_results_path: path to the result folder
    :param filenames:
    :param filename_syscall_dict:
    :return:
    """
    with open(dir_results_path + '/syscalls.txt', 'w', encoding='utf-8',
              errors='replace') as res_file:
        for filename in filenames:
            total_syscall = 0
            res_file.write('{} {}\n'.format(string_utils.filename, filename))
            if filename in filename_syscall_dict:
                entry = filename_syscall_dict[filename]
                total_syscall = sum(entry.values())

            res_file.write('{} {}\n\n'.format(string_utils.syscall_final, total_syscall))


def output_clues(dir_results_path: str, clues_dict: dict, out_file_name: str):
    """
    Prints the list of suspect log files with the clue elements to a file.

    :param dir_results_path: path to the result folder
    :param clues_dict:
    :param out_file_name:
    :return:
    """
    with open(dir_results_path + '/' + out_file_name, 'w', encoding='utf-8', errors='replace') as clues_file:
        filenames = sorted(list(clues_dict.keys()))
        for filename in filenames:
            clue = clues_dict[filename]
            clues_file.write(domain_utils.repr_clue(clue) + '\n\n')


def output_suspects(dir_results_path, suspects):
    """
    Prints the suspects dictionary into a human readable file.

    :param dir_results_path: path to the result folder
    :param suspects:
    :return:
    """
    with open(dir_results_path + '/suspects.txt', 'w', encoding='utf-8', errors='replace') as suspects_file:
        sorted_filenames = sorted(list(suspects.keys()))
        for filename in sorted_filenames:
            suspects_file.write(
                '{}\t{}\n'.format(string_utils.filename, filename)
            )
            for orig_mal, index in suspects[filename].items():
                if orig_mal is not None:
                    suspects_file.write(
                        '{}\t{}\t{}\n'.format(string_utils.original_mal, orig_mal[0], orig_mal[1])
                    )
                    suspects_file.write(
                        '{}\t{}\n\n'.format(string_utils.suspect_ind, index)
                    )
                else:
                    suspects_file.write('\n\n\n')


def output_json(file_name, domain_object, output_dir):
    """
    Output the specified domain object on a file in json format using the JsonPickle library.
    The object can later be loaded form the file directly into a memory object.
    
    :param file_name: output file name 
    :param domain_object: the object to output
    :param output_dir: path to the output directory
    :return: 
    """

    with open(path.join(output_dir, file_name + '.json'), 'w', encoding='utf-8', errors='replace') as out_file:
        json_object = jsonpickle.encode(domain_object)
        out_file.write(json_object)
        out_file.write('\n')
