from pandaloginvestigator.core.utils import string_utils
import subprocess
import logging
import os

"""
This module handles utility methods which are inherently related to Panda or the pandalogs structure.
"""


logger = logging.getLogger(__name__)


def unpack_log(dir_panda_path, filename, dir_pandalogs_path, dir_unpacked_path):
    """
    Unpack the specified log file using the PANDA 'pandalog_reader' utility.
    The content of the log will be saved in a file with the same name in a
    folder under the created_dirs_path specified in the configuration.

    :param dir_panda_path: path to the pandalog unpacker utility
    :param filename: pandalog file to unpack
    :param dir_pandalogs_path: path to the pandalogs directory
    :param dir_unpacked_path: path to the unpacked pandalogs directory
    :return:
    """

    unpack_command = 'pandalog_reader'
    reduced_filename = filename[:-9] if string_utils.ext_pandalog_file in filename else filename
    logger.debug('unpacking = ' + str(filename))
    return_code = subprocess.call(os.path.join(dir_panda_path, unpack_command) + " " +
                                  os.path.join(dir_pandalogs_path, filename) + " > " +
                                  os.path.join(dir_unpacked_path, reduced_filename),
                                  shell=True)
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
    Handles linux problems with windows style path strings.

    :param line: current line of the pandalog
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

    :param line: current line of the pandalog
    :return: path to the written file
    """

    fixed_substring = u'filename,'
    index = line.find(fixed_substring)
    line = line[index:]
    return os.path.normpath(line.strip().split(',')[1].split(')')[0])


def data_from_line_double(line, creating=False):
    """
    Given a line of the log file returns:
     * instruction counter
     * pid of the caller
     * process name of the caller
     * pid of the callee
     * process name of the callee 
     * optionally path to the executable if present

    :param line: current line of the pandalog
    :param creating: flag retrieve path of executable
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

    return current_instruction, subject_pid, subject_name, object_pid, object_name


def data_from_line(line, writing=False, registry=False, registry_query=False):
    """
    Given a line of the log file returns:
     * instruction counter
     * pid of the caller
     * process name of the caller
     * optionally path to the written file if present

    :param line: current line of the pandalog
    :param writing: flag, retrieve path written file
    :param registry: flag, retrieve registry key
    :param registry_query: flag, retrieve registry query parameters
    :return: list of elements of the panda log file line
    """
    commas = line.strip().split(',')
    current_instruction = int((commas[0].split()[0].split('='))[1])
    pid = int(commas[2].strip())
    process_name = commas[3].split(')')[0].strip()

    if writing:
        file_path = get_written_file_path(line)
        return current_instruction, pid, process_name, file_path

    if registry:
        registry_key = commas[4].split(')')[0].strip()
        return current_instruction, pid, process_name, registry_key

    if registry_query:
        registry_key = commas[4].split(')')[0].strip()
        query_parameters = commas[5].split(')')[0].strip()
        return current_instruction, pid, process_name, registry_key, query_parameters

    return current_instruction, pid, process_name
