from pandaloginvestigator.core.utils import string_utils
from os import path
import jsonpickle


"""
This file contains methods used to output partial and global results on file. 
"""


def output_suspects(dir_results_path, suspects):
    """
    Prints the suspects dictionary into a human readable file.

    :param dir_results_path: path to the result folder
    :param suspects:
    :return:
    """
    with open(path.join(dir_results_path, 'suspects.txt'), 'w', encoding='utf-8', errors='replace') as suspects_file:
        sorted_file_names = sorted(list(suspects.keys()))
        for file_name in sorted_file_names:
            suspects_file.write('{}\t{}\n'.format(string_utils.filename, file_name))
            suspects_file.write('{}\t{}\n\n'.format(string_utils.suspect_ind, suspects[file_name]))


def output_json(file_name, domain_object, output_dir):
    """
    Outputs the specified domain object on a file in json format using the JsonPickle library.
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


def final_output_analysis(samples_dict, dir_results_path):
    """
    Outputs the final analysis results on file.
    It creates 3 files:
     * for each sample it shows the numeric values collected for instructions
     * for each sample it shows the numeric values collected for system calls
     * for each sample it shows the structure of corrupted processes observed
    
    :param samples_dict: dictionary of ReducedSample objects 
    :param dir_results_path: path to results directory
    :return: 
    """
    with open(path.join(dir_results_path, 'corrupted_processes.txt'), 'w', encoding='utf-8', errors='replace') as c_out:
        with open(path.join(dir_results_path, 'analysis.txt'), 'w', encoding='utf-8', errors='replace') as i_out:
            with open(path.join(dir_results_path, 'syscalls.txt'), 'w', encoding='utf-8', errors='replace') as s_out:
                for uuid in sorted(samples_dict.keys()):
                    reduced_sample = samples_dict[uuid]

                    i_out.write('{} {}\n'.format(string_utils.filename, uuid))
                    s_out.write('{} {}\n'.format(string_utils.filename, uuid))
                    c_out.write('{} {}\n'.format(string_utils.filename, uuid))

                    # corrupted processes section
                    process_repr = '\t\t{:15s}\t{:10d}\t{:15s}\tby:\t{:15s}\t{:10d}\n'
                    for process in reduced_sample.corrupted_processes:
                        c_out.write(process_repr.format(process[0],
                                                        process[1],
                                                        process[2],
                                                        process[3],
                                                        process[4]))

                    # instruction count section
                    i_out.write(string_utils.out_final + '\t' + str(reduced_sample.total_instruction) + '\n')
                    i_out.write(string_utils.out_terminating + '\t' + str(reduced_sample.terminate_all) + '\t')
                    i_out.write(string_utils.out_sleeping + '\t' + str(reduced_sample.sleep_all) + '\t')
                    i_out.write(string_utils.out_crashing + '\t' + str(reduced_sample.crash_all) + '\t')
                    i_out.write(string_utils.out_raising_error + '\t' + str(reduced_sample.error_all) + '\t')
                    i_out.write(string_utils.out_writes_file + '\t' + str(reduced_sample.write_file) + '\n')

                    # system calls count section
                    s_out.write(string_utils.syscall_final + '\t' + str(reduced_sample.total_syscalls) + '\n')

                    i_out.write('\n')
                    s_out.write('\n')
                    c_out.write('\n')
