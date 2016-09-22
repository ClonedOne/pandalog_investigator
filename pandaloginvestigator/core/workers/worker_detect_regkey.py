from pandaloginvestigator.core.domain.suspect import Suspect
import logging


logger = logging.getLogger(__name__)


def work(data_pack):
    suspect_dict = {}
    worker_id = data_pack[0]
    filenames = data_pack[1]
    tags_reg_key = data_pack[2]
    dir_unpacked_path = data_pack[3]
    tags_reg_value = dict([reversed(i) for i in tags_reg_key.items()])
    j = 0.0
    total_files = len(filenames) if len(filenames) > 0 else -1
    logger.info('WorkerId ' + str(worker_id) + ' detecting ' + str(total_files) + ' log files')
    for filename in filenames:
        suspect_dict[filename] = Suspect(filename)
        with open(dir_unpacked_path + '/' + filename, encoding='utf-8', errors='replace') as log_file:
            for line in log_file:
                for value in tags_reg_value:
                    if value in line:
                        tag = tags_reg_value[value]
                        instr_num = line.split('=')[1].split()[0]
                        process_id = line.split(',')[2].strip()
                        process_name = line.split(',')[3].split(')')[0].strip()
                        suspect_dict[filename].add_tag_occ(tag, (instr_num, process_id, process_name))
        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_files)))
    return (suspect_dict, )
