from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.io import file_input
import logging
import time
import os
import pprint
import jsonpickle

logger = logging.getLogger(__name__)


def work(data_pack):
    """
     Pandalog detection worker main method. The data passed to each worker contains:
     * worker id - 0
     * list of file names to analyze - 1
     * path to the clues files directory - 2
     * path to the analyzed logs directory - 3
     * dictionary containing dangerous registry keys and values - 4
    
    :param data_pack: data needed by the worker  
    :return: dictionary of Clue objects
    """

    j = 0.0
    clues_dict = {}
    red_pills = False
    starting_time = time.time()

    # Unpacking of the passed data
    worker_id = data_pack[0]
    file_names = data_pack[1]
    dir_clues_path = data_pack[2]
    dir_analyzed_path = data_pack[3]
    registry_keys = data_pack[4]['keys']
    registry_values = data_pack[4]['values']

    # performance optimization
    features = [
        string_utils.current_process,
        string_utils.current_pid,
        string_utils.parent_pid,
        string_utils.instruction_mnemonic,
        string_utils.instruction_operands,
        string_utils.instruction_size,
        string_utils.instruction_bytes
    ]

    total_files = len(file_names)
    logger.info('WorkerId {} reading {} clues files'.format(worker_id, total_files))

    if os.path.exists(dir_clues_path):
        red_pills = True

    for file_name in file_names:

        current_clue = Clue(file_name)
        current_sample = file_input.load_sample(file_name, dir_analyzed_path)

        # Avoid empty or crashing samples
        if not current_sample.corrupted_processes or current_sample.crash_all() or current_sample.error_all():
            continue

        examine_registry_activity(current_clue, current_sample, registry_keys, registry_values)

        if red_pills:
            examine_red_pills(current_clue, current_sample, dir_clues_path, file_name, features)

        examine_special_status(current_clue, current_sample)

        clues_dict[file_name] = current_clue

        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))

    total_time = time.time() - starting_time
    logger.info('WorkerId ' + str(worker_id) + ' Total time: ' + str(total_time))
    return clues_dict


def examine_registry_activity(clue, sample, registry_keys, registry_values):
    """
    Examine the Sample object looking for accesses and queries to dangerous registry key entries.
    
    :param clue: Clue object to modify
    :param sample: Sample object to examine
    :param registry_keys: list of dangerous keys
    :param registry_values: list of dangerous values
    :return: 
    """

    for process_info, process in sample.corrupted_processes.items():
        accessed_keys = set()
        queried_values = set()
        for accessed_key, queried_value in process.registry_activity.items():
            accessed_keys.add(accessed_key)
            queried_values |= queried_value

        for registry_key in registry_keys:
            if registry_key in accessed_keys:
                clue.opened_keys[process_info] = clue.opened_keys.get(process_info, set())
                clue.opened_keys[process_info].add(registry_key)

        for registry_value in registry_values:
            if registry_value in queried_values:
                clue.queried_values[process_info] = clue.queried_values.get(process_info, set())
                clue.queried_values[process_info].add(registry_value)


def examine_red_pills(clue, sample, dir_clues_path, file_name, features):
    """
    Gather information about red pills discovered by the PANDA plugin.
    
    :param clue: Clue object to modify
    :param sample: Sample object examined
    :param dir_clues_path: path to the clues files directory
    :param file_name: name of the clues file
    :param features: fixed elements of the clues file
    :return: 
    """

    with open(os.path.join(dir_clues_path, file_name + '_ss.txt'), encoding='utf-8', errors='replace') as clue_file:
        cur_features = [None] * 7

        for line in clue_file:

            if not line.strip() and cur_features[0] is not None:
                current_process = (cur_features[0], int(cur_features[1]))

                if str(current_process) in list(sample.corrupted_processes.keys()):
                    if int(cur_features[5]) >= 15:
                        instruction = string_utils.tag_dangerous[0]
                    else:
                        instruction = cur_features[3]
                    clue.red_pills[current_process] = clue.red_pills.get(current_process, set())
                    clue.red_pills[current_process].add(instruction)
                cur_features = [None] * 7

            else:
                split_line = line.split(':')
                for i in range(len(features)):
                    if features[i] == split_line[0]:
                        cur_features[i] = split_line[1].strip()


def examine_special_status(clue, sample):
    """
    Examine the Sample object looking for dangerous features of the sample execution.
    
    :param clue: Clue object to modify
    :param sample: Sample object examined
    :return: 
    """

    if sample.terminate_all():
        clue.termination = True

    if sample.sleep_all():
        clue.sleep = True

    if sample.write_file():
        clue.write_file = True

    instructions = sample.total_instruction()

    if instructions[3] < Clue.FIRST_POPULATION:
        clue.low_instruction = True

    if instructions[1] + instructions[2] != 0:
        clue.create_write_process = True

