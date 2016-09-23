import subprocess
import os
import logging


# This module handles utility methods which are inherently related to Panda or
# the panda logs structure.


logger = logging.getLogger(__name__)


# Unpack the specified log file using the PANDA 'pandalog_reader' utility.
# The content of the log will be saved in a temporary file with the same name.
def unpack_log(dir_panda_path, filename, dir_pandalogs_path, dir_unpacked_path):
    unpack_command = '/pandalog_reader'
    reduced_filename = filename[:-9]
    return_code = subprocess.call(dir_panda_path + unpack_command + " " + dir_pandalogs_path + '/' + filename + " > " +
                                  dir_unpacked_path + '/' + reduced_filename, shell=True)
    if return_code != 0:
        logger.debug('Unpack log: ' + reduced_filename + 'return code: ' + str(return_code))


# Handles the acquisition of the path string from the log file.
# It is used to handle linux problems with windows style path strings.
def get_new_path(path_input):
    words = path_input.split()
    line = ''
    fixed_substring = 'name=['
    for word in words:
        line += word + ' '
    index = line.find(fixed_substring)
    line = line[index:]
    return os.path.normpath(line.split('[')[1].replace(']', ''))


# Updates the process id <-> process name dictionaries (direct and inverted).
# At each context switch the new couple (pid, process_name) is
# either added or its frequency is updated inside the dictionaries.
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


# Given a line of the log file returns the instruction
def data_from_line(line, creating=False):
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    subject_pid = int(commas[2].strip())
    subject_name = commas[3].split(')')[0].strip()
    object_pid = int(commas[5].strip())
    object_name = commas[6].split(')')[0].strip()
    if creating:
        new_path = get_new_path(line)
        return current_instruction, subject_pid, subject_name, object_pid, object_name, new_path
    else:
        return current_instruction, subject_pid, subject_name, object_pid, object_name


# Adapted version of get_data_from_line for the detector
def data_from_line_d(line):
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    subject_pid = int(commas[2].strip())
    subject_name = commas[3].split(')')[0].strip()
    return current_instruction, subject_pid, subject_name
