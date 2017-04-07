from pandaloginvestigator.core.workers import worker_clues_reader
from pandaloginvestigator.core.io import file_output, file_input
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import utils
from multiprocessing import Pool
import logging
import time
import os
import pprint


logger = logging.getLogger(__name__)


def build_suspects(dir_results_path, dir_clues_path, dir_analyzed_path, core_num):
    """
    Builds the final list of suspect processes. The outcome is based on the analysis output and the red-pills
    discovered. It ends by passing the computed list to the on file output handler.

    :param dir_results_path: path to the result directory
    :param dir_clues_path: path to the Investigator plugin results directory
    :param dir_analyzed_path: path to the analysis results
    :param core_num: number of cores available
    :return:
    """

    logger.info('Starting gathering suspects')
    clues_dict = {}
    t1 = time.time()

    file_names = retrieve_file_list(dir_analyzed_path)
    registry_keys = file_input.get_registry_keys()

    file_names_sublists = utils.divide_workload(file_names, core_num, len(file_names))
    formatted_input = utils.format_worker_input(
        core_num,
        file_names_sublists,
        (
            dir_clues_path,
            dir_analyzed_path,
            registry_keys
        )
    )
    pool = Pool(processes=core_num)
    results = pool.map(worker_clues_reader.work, formatted_input)
    pool.close()
    pool.join()
    utils.update_results(results, clues_dict)

    # file_output.output_clues(dir_results_path, clues_dict, 'total_clues.txt')

    suspects = sum_suspects(clues_dict)
    normalize_suspects(suspects)

    # file_output.output_suspects(dir_results_path, suspects)

    pprint.pprint(suspects)

    logger.info('Total suspects gathering time: ' + str(time.time() - t1))


def sum_suspects(clues):
    """
    Sum the suspect elements of a clue object to obtain a numerical index.

    :param clues: Dictionary of clues object by sample uuid
    :return: dictionary mapping file names to int
    """
    suspects = {}

    # Particularly dangerous instructions
    danger = set(string_utils.tag_dangerous)

    for file_name, clue in clues.items():
        index = 0

        already_considered = set()
        for process, keys in clue.opened_keys.items():
            already_considered |= keys
        for process, values in clue.queried_values.items():
            already_considered |= values
        for process, red_pills in clue.red_pills.items():
            already_considered |= red_pills
        index += len(already_considered)

        index += 5 * len(danger & already_considered)

        if clue.sleep:
            index += 1

        if clue.termination:
            index += 1
            if not clue.write_file:
                index += 1
            if not clue.create_write_process:
                index += 1
            if clue.low_instruction:
                index += 1

        suspects[file_name] = index

    return suspects


def normalize_suspects(suspects):
    """
    Normalizes the values in suspects dictionary.
    As reference value uses the suspect value of PaFish, a known sandbox evasion test.

    :param suspects:
    :return:
    """
    PAFISH_VALUE = 11.0
    for filename, cur_val in suspects.items():
        suspects[filename] = cur_val / PAFISH_VALUE


def retrieve_file_list(dir_analyzed_path):
    """
    Retrieves the list of files to examine form the analyzed logs directory.
    Strips each file name from the extension.
    
    :param dir_analyzed_path: path to the analysis results
    :return: list of file names to examine
    """

    return [os.path.splitext(file_name)[0] for file_name in os.listdir(dir_analyzed_path)]
