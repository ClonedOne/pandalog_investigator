import logging
import codecs


system_call_tag = u'nt_any_syscall (num='

logger = logging.getLogger(__name__)


# For each file in the filenames list, uses the system call dictionary passed to translate the system calls
# from number to explicit names, and save it to a separate folder.
def work(data_pack):
    worker_id = data_pack[0]
    filenames = data_pack[1]
    dir_unpacked_path = data_pack[2]
    dir_translated_path = data_pack[3]
    syscall_dict = data_pack[4]
    j = 0.0
    total_files = len(filenames)
    logger.info('WorkerId = ' + str(worker_id) + ' translating ' + str(total_files) + ' log files')
    for filename in filenames:
        j += 1
        logger.info('Translator ' + str(worker_id) + ' ' + str(j / total_files * 100) + '%')
        with codecs.open(dir_unpacked_path + '/' + filename, 'r', 'utf-8', errors='ignore') as log_file:
            with codecs.open(dir_translated_path + '/' + filename, 'w', 'utf-8', errors='ignore') as translated_file:
                for line in log_file:
                    if system_call_tag in line:
                        system_call_num = int(line.split('=')[3].split(')')[0])
                        system_call = syscall_dict.get(system_call_num, system_call_num)
                        new_line = line.split(':')[0] + ': ' + str(system_call) + '\n'
                        translated_file.write(new_line)
                    else:
                        translated_file.write(line)
