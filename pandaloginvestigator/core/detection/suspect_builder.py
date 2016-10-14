from pandaloginvestigator.core.utils import results_reader
from pandaloginvestigator.core.domain.malware_object import Malware
from pandaloginvestigator.core.utils import file_utils
import logging


logger = logging.getLogger(__name__)


def build_suspects(dir_results_path, dir_clues_path):
    corrupted_dict = results_reader.read_result_corrupted(dir_results_path)
    suspects_multiproc = initalize_suspects(corrupted_dict)
    clues_regkey_dict = results_reader.read_clues_regkey(dir_results_path)
    for filename, processes in clues_regkey_dict.items():
        if filename in suspects_multiproc:
            for process in processes:
                if process in suspects_multiproc[filename]:
                    suspects_multiproc[filename][process] += clues_regkey_dict[filename][process]
    suspects = sum_suspects(suspects_multiproc, corrupted_dict)
    normalize_suspects(suspects)
    file_utils.output_suspects(dir_results_path, suspects)


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
