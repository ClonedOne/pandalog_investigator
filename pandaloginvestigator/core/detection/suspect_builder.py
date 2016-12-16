from pandaloginvestigator.core.domain.malware_object import Malware
from pandaloginvestigator.core.domain.clue_object import Clue
from pandaloginvestigator.core.detection import worker_clues_reader
from pandaloginvestigator.core.utils import results_reader
from pandaloginvestigator.core.utils import domain_utils
from pandaloginvestigator.core.utils import string_utils
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.utils import utils
from multiprocessing import Pool
import logging
import os
import time

logger = logging.getLogger(__name__)


def build_suspects(dir_results_path, dir_clues_path, core_num):
    corrupted_dict = results_reader.read_result_corrupted(dir_results_path)
    clues = initialize_clues(corrupted_dict)

    clues_regkey_dict = results_reader.read_clues_regkey(dir_results_path)
    add_clues(clues, clues_regkey_dict)

    clues_from_panda = {}
    t1 = time.time()
    if os.path.exists(dir_clues_path):
        filenames = sorted(os.listdir(dir_clues_path))
        file_names_sublists = utils.divide_workload(filenames, core_num)
        formatted_input = utils.format_worker_input(
            core_num,
            file_names_sublists,
            (
                dir_clues_path,
                corrupted_dict
            )
        )
        pool = Pool(processes=core_num)
        results = pool.map(worker_clues_reader.work, formatted_input)
        pool.close()
        logger.info('Total clue reading time: ' + str(time.time() - t1))
        utils.update_results(results, [clues_from_panda, ])
    add_clues(clues, clues_from_panda)
    file_utils.output_clues(dir_results_path, clues, 'total_clues.txt')
    suspects = sum_suspects(clues, corrupted_dict)
    analysis_results = results_reader.read_data(dir_results_path, string_utils.target_i)
    suspects = remove_crashed(suspects, analysis_results[6], analysis_results[7])
    file_utils.output_clues(dir_results_path, clues, 'total_clues_corrupted_only.txt')
    add_status_modifier(suspects, analysis_results)
    normalize_suspects(suspects)

    file_utils.output_suspects(dir_results_path, suspects)


def initialize_clues(corrupted_dict):
    """
    Initialize the clue dictionary to empty clues.

    :param corrupted_dict:
    :return:
    """
    clues = {}
    for filename, processes in corrupted_dict.items():
        clues[filename] = Clue(filename)
    return clues


def add_clues(clues, new_clues_dict):
    """
    Add newly discovered clues in new_clues_dict to previously found clues

    :param clues:
    :param new_clues_dict:
    :return:
    """
    for filename in clues:
        if filename in new_clues_dict:
            clues[filename] = domain_utils.merge_clues(clues[filename], new_clues_dict[filename])


def sum_suspects(clues, corrupted_dict):
    """
    Sum the values of different corrupted processes to obtain a single
    value relative to the original malware.

    :param clues:
    :param corrupted_dict:
    :return: dictionary mapping file names to int
    """
    suspects = {}
    # Used to reflect the danger related to those instructions
    danger = string_utils.tag_dangerous
    for filename in clues:
        if filename in corrupted_dict:
            original_proc = None
            corrupted_procs = []
            for process in corrupted_dict[filename]:
                if Malware.FROM_DB in process:
                    original_proc = process[0]
                corrupted_procs.append(process[0])
            acc_value = 0.0
            cur_clue = clues[filename]
            cur_clue_procs = cur_clue.get_processes()

            for proc in cur_clue_procs:
                if proc not in corrupted_procs:
                    cur_clue.remove_process(proc)

            already_considered = set()
            for proc in cur_clue.get_processes():
                for sub_dict in cur_clue.get_everything_proc(proc):
                    for key in sub_dict:
                        if key not in already_considered:
                            acc_value += 1
                            if key in danger:
                                acc_value += 5
                            already_considered.add(key)
            suspects[filename] = {original_proc: acc_value}
    return suspects


def normalize_suspects(suspects):
    """
    Normalize the values in suspects dictionary. As reference use
    the suspect value of PaFish, a known sandbox evasion test.

    :param suspects:
    :return:
    """
    pafish_val = 11.0
    for filename, processes in suspects.items():
        for process, cur_val in processes.items():
            processes[process] = cur_val / pafish_val


def add_status_modifier(suspects, analysis_results):
    """
    Add a modifier for the special status conditions.
    1 point for termination of all processes
    1 point for sleep on all processes
    1 point for termination of all processes without having written
    at least one file
    1 point for termination of all processes without having executed
    any instructions with spawned/memory written processes
    1 point for termination with an instruction count below the
    second population of the 25th percentile

    :param suspects:
    :param analysis_results:
    :return:
    """
    inside_first_population = 40000000
    totals_dict = analysis_results[0]
    created_dict = analysis_results[2]
    written_dict = analysis_results[3]
    terminating_dict = analysis_results[4]
    sleeping_dict = analysis_results[5]
    filewrite_dict = analysis_results[8]
    for filename in suspects:
        modifier = 0
        if terminating_dict.get(filename, False):
            modifier += 1
            if not filewrite_dict.get(filename, False):
                modifier += 1
            if (created_dict.get(filename, 0) + written_dict.get(filename, 0)) == 0:
                modifier += 1
            if totals_dict.get(filename, 0) < inside_first_population:
                modifier += 1

        if sleeping_dict.get(filename, False):
            modifier += 1

        for proc in suspects[filename]:
            suspects[filename][proc] += modifier


def remove_crashed(suspects, crashing_dict, error_dict):
    """
    Remove crashed and error rising samples from the suspects.

    :param suspects:
    :param crashing_dict:
    :param error_dict:
    :return:
    """
    clean_suspects = {}
    for key, value in suspects.items():
        if crashing_dict.get(key, False) or error_dict.get(key, False):
            continue
        else:
            clean_suspects[key] = value
    return clean_suspects
