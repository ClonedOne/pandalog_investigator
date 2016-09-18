from pandaloginvestigator.core.utils import string_utils
import logging

no_instructions = string_utils.no_instructions
logger = logging.getLogger(__name__)


# Wrapper used to provide the correct data to both plotter methods.
def accumulate_data(dir_results_path, target):
    if target == target_i:
        accumulate_data_instr(dir_results_path)
    elif target == target_s:
        accumulate_data_syscall(dir_results_path)


def accumulate_data_instr(dir_results_path):
    next_file_name = True
    next_values = False
    next_term_sleep = False

    with open(dir_results_path + '/analysis.txt', 'r', encoding='utf-8',
              errors='replace') as resfile:
        last_file_name = ''
        for line in resfile:
            if not line.strip():
                next_file_name = True
                continue
            line = line.strip()
            if next_file_name:
                filename = line.split()[2]
                last_file_name = filename
                next_file_name = False
                next_values = True
                continue
            if next_values:
                if line != no_instructions:
                    values = line.split('\t')[1].replace(
                        '[', '').replace(']', '').replace(',', '').split()
                    from_db_dict[last_file_name] = int(values[0])
                    if int(values[1]) > 0:
                        created_dict[last_file_name] = int(values[1])
                    if int(values[2]) > 0:
                        written_dict[last_file_name] = int(values[2])
                    totals_dict[last_file_name] = int(values[3])
                next_values = False
                next_term_sleep = True
                continue
            if next_term_sleep:
                values = line.split('\t')
                terminating_dict[last_file_name] = ast.literal_eval(values[
                                                                    1].strip())
                sleeping_dict[last_file_name] = ast.literal_eval(values[
                                                                 3].strip())
                crashing_dict[last_file_name] = ast.literal_eval(values[
                                                                 5].strip())
                error_dict[last_file_name] = ast.literal_eval(
                    values[7].strip())
                next_term_sleep = False

