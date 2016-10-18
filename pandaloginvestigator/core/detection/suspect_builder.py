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
    clues = initalize_clues(corrupted_dict)

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

    suspects = sum_suspects(clues, corrupted_dict)
    analysis_results = results_reader.read_data(dir_results_path, string_utils.target_i)
    add_status_modifier(suspects, analysis_results)
    normalize_suspects(suspects)

    file_utils.output_suspects(dir_results_path, suspects)


def initalize_clues(corrupted_dict):
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

            for proc in cur_clue.get_processes():
                for sub_dict in cur_clue.get_everything_proc(proc):
                    for i in range(len(sub_dict)):
                        acc_value += 1
            suspects[filename] = {original_proc: acc_value}
    return suspects


def normalize_suspects(suspects):
    """
    Normalize the values in suspects dictionary to obtain an
    index between 0 and 1

    :param suspects:
    :return:
    """
    max_val = 0.0
    for filename, processes in suspects.items():
        for process, cur_val in processes.items():
            if cur_val > max_val:
                max_val = cur_val
    for filename, processes in suspects.items():
        for process, cur_val in processes.items():
            processes[process] = cur_val / max_val


def add_status_modifier(suspects, analysis_results):
    """
    Add a modifier for the special status condition of processes.
    2 points for termination of all processes
    1 point for sleep on all porcesses

    :param suspects:
    :param analysis_results:
    :return:
    """
    terminating_dict = analysis_results[4]
    sleeping_dict = analysis_results[5]
    for filename in suspects:
        if terminating_dict.get(filename, False):
            for proc in suspects[filename]:
                suspects[filename][proc] += 2
        if sleeping_dict.get(filename, False):
            for proc in suspects[filename]:
                suspects[filename][proc] += 1
