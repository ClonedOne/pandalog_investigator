from pandaloginvestigator.core.domain.malware_object import Malware
from pandaloginvestigator.core.detection import worker_clues_reader
from pandaloginvestigator.core.utils import results_reader
from pandaloginvestigator.core.utils import file_utils
from pandaloginvestigator.core.utils import utils
from multiprocessing import Pool
import logging
import os
import time

logger = logging.getLogger(__name__)


def build_suspects(dir_results_path, dir_clues_path, core_num):
    corrupted_dict = results_reader.read_result_corrupted(dir_results_path)
    suspects_multiproc = initalize_suspects(corrupted_dict)
    clues_regkey_dict = results_reader.read_clues_regkey(dir_results_path)
    add_clues(suspects_multiproc, clues_regkey_dict)
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
        update_suspects_multiproc(suspects_multiproc, results)

    suspects = sum_suspects(suspects_multiproc, corrupted_dict)
    normalize_suspects(suspects)
    file_utils.output_suspects(dir_results_path, suspects)


# Add clues in clues_dict to suspects in suspects_dict
def add_clues(suspects_dict, clues_dict):
    for filename, processes in clues_dict.items():
        if filename in suspects_dict:
            for process in processes:
                if process in suspects_dict[filename]:
                    suspects_dict[filename][process] += clues_dict[filename][process]


# Initialize the suspects dictionary to all zeroes considering
# only corrupted processes
def initalize_suspects(corrupted_dict):
    suspects_multiproc = {}
    for filename, processes in corrupted_dict.items():
        suspects_multiproc[filename] = {}
        for process in processes:
            proc = process[0]
            suspects_multiproc[filename][proc] = 0
    return suspects_multiproc


# Sum the values of different corrupted processes to obtain a single
# value relative to the original malware.
def sum_suspects(suspects_multiproc, corrupted_dict):
    suspects = {}
    for filename in suspects_multiproc:
        if filename in corrupted_dict:
            original_proc = None
            for process in corrupted_dict[filename]:
                if Malware.FROM_DB in process:
                    original_proc = process[0]
            acc_value = 0.0
            for process in suspects_multiproc[filename]:
                acc_value += suspects_multiproc[filename][process]
            suspects[filename] = {original_proc: acc_value}
    return suspects


# Normalize the values in suspects dictionary to obtain an
# index between 0 and 1
def normalize_suspects(suspects):
    max_val = 0.0
    for filename, processes in suspects.items():
        for process, cur_val in processes.items():
            if cur_val > max_val:
                max_val = cur_val
    for filename, processes in suspects.items():
        for process, cur_val in processes.items():
            processes[process] = cur_val / max_val


# Add values form clues files reading to already computed suspects_multiproc
def update_suspects_multiproc(suspects_multiproc, results):
    for result in results:
        for filename in result[0]:
            suspects = suspects_multiproc.get(filename, {})
            for proc in result[0][filename]:
                suspects[proc] = suspects.get(proc, 0) + result[0][filename][proc]
