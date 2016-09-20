from collections import defaultdict
import logging


logger = logging.getLogger(__name__)


def work(data_pack):
    filename_regkey_dict = defaultdict(defaultdict(int))
    worker_id = data_pack[0]
    filenames = data_pack[1]
    tags_reg_key = data_pack[2]
    dir_unpacked_path = data_pack[3]
    tags_reg_value = dict([reversed(i) for i in tags_reg_key.items()])
    j = 0.0
    total_files = len(filenames) if len(filenames) > 0 else -1
    for filename in filenames:
        with open(dir_unpacked_path + '/' + filename, encoding='utf-8', errors='replace') as log_file:
            for line in log_file:
                for value in tags_reg_value:
                    if value in line:
                        tag = tags_reg_value[value]
                        filename_regkey_dict[filename][tag] += 1

