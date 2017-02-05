from pandaloginvestigator.core.utils import string_utils
import subprocess
import logging
import os


# This module handles utility methods which are inherently related to Panda or
# the panda logs structure.


logger = logging.getLogger(__name__)


def unpack_log(dir_panda_path, filename, dir_pandalogs_path, dir_unpacked_path):
    """
    Unpack the specified log file using the PANDA 'pandalog_reader' utility.
    The content of the log will be saved in a file with the same name in a
    folder under the created_dirs_path specified in the configuration.

    :param dir_panda_path:
    :param filename:
    :param dir_pandalogs_path:
    :param dir_unpacked_path:
    :return:
    """
    unpack_command = '/pandalog_reader'
    reduced_filename = filename[:-9] if string_utils.ext_pandalog_file in filename else filename
    logger.debug('unpacking = ' + str(filename))
    return_code = subprocess.call(dir_panda_path + unpack_command + " " + dir_pandalogs_path + '/' + filename + " > " +
                                  dir_unpacked_path + '/' + reduced_filename, shell=True)
    if return_code != 0:
        logger.debug('Unpack log: ' + reduced_filename + 'return code: ' + str(return_code))


def remove_log_file(filename, dir_unpacked_path):
    """
    Delete the temporary unpacked log file to avoid disk congestion.
    Used if the --small-disk flag is specified as parameter to commands.

    :param filename:
    :param dir_unpacked_path:
    :return:
    """
    os.remove(dir_unpacked_path + '/' + filename)


def get_new_path(line):
    """
    Handles the acquisition of the path string for a created process.
    It is used to handle linux problems with windows style path strings.

    :param line:
    :return: path to the created process executable
    """
    fixed_substring = u'name=['
    index = line.find(fixed_substring)
    line = line[index:]
    return os.path.normpath(line.strip().split('[')[1].replace(']', ''))


def get_written_file_path(line):
    """
    Handles the acquisition of the path string for a written file.
    It is used to handle linux problems with windows style path strings.

    :param line:
    :return:
    """
    fixed_substring = u'filename,'
    index = line.find(fixed_substring)
    line = line[index:]
    return os.path.normpath(line.strip().split(',')[1].split(')')[0])


def update_dictionaries(pid, process_dict, proc_name, inverted_process_dict):
    """
    Updates the process id <-> process name dictionaries (direct and
    inverted). At each context switch the new couple (pid, process_name)
    is either added or its frequency is updated inside the dictionaries.

    :param pid:
    :param process_dict:
    :param proc_name:
    :param inverted_process_dict:
    :return:
    """
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


def data_from_line(line, creating=False):
    """
    Given a line of the log file returns the instruction counter, pid of
    the caller, process name of the caller, pid of the callee, process name
     of the callee and optionally the path to the executable if present.

    :param line:
    :param creating:
    :return: list of elements of the panda log file line
    """
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


def data_from_line_basic(line):
    """
    Basic version of get_data_from_line. Returns the instruction counter,
    pid of the caller, process name of the caller.

    :param line:
    :return: list of elements of the panda log file line
    """
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    subject_pid = int(commas[2].strip())
    subject_name = commas[3].split(')')[0].strip()
    return current_instruction, subject_pid, subject_name
