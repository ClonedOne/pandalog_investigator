from pandaloginvestigator.core.utils import results_reader
import logging
import sys


logger = logging.getLogger(__name__)


def build_suspects(dir_results_path, dir_clues_path):
    corrupted_dict = results_reader.read_result_corrupted(dir_results_path)
    suspects = initalize_suspects(corrupted_dict)
    clues_regkey_dict = results_reader.read_clues_regkey(dir_results_path)
    for filename, processes in clues_regkey_dict.items():
        if filename in suspects:
            for process in processes:
                if process in suspects[filename]:
                    suspects[filename][process] += clues_regkey_dict[filename][process]
    normalize_suspects(suspects)
    print(suspects)


# Initialize the suspects dictionary to all zeroes considering
# only corrupted processes
def initalize_suspects(corrupted_dict):
    suspects = {}
    for filename, processes in corrupted_dict.items():
        suspects[filename] = {}
        for process in processes:
            proc = process[0]
            suspects[filename][proc] = 0
    return suspects


# Normalize the values in suspects dictionary to give an
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
