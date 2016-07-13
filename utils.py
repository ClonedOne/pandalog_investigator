import pprint
import subprocess
import os


def unpack_log(filename, unpack_command, dir_pandalogs_path, dir_unpacked_path):
    print 'unpacking: ' + filename
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + filename + ".txt", shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


def get_new_path(words):
    line = ''
    fixed = 'name=['
    for word in words:
        line += word + ' '
    index = line.find(fixed)
    line = line[index:]
    return os.path.normpath(line.split('[')[1].replace(']', ''))


def output_on_file(filename, process_dict, inverted_process_dict, dir_analyzed_logs,
                   db_file_malware_dict, file_corrupted_processes_dict):
    outfile = open(dir_analyzed_logs + filename + '_a.txt', 'w')
    total_instruction_accumulator = [0, 0, 0, 0]
    pprint.pprint(process_dict, outfile)
    outfile.write('\n')
    pprint.pprint(inverted_process_dict, outfile)
    outfile.write('\n')
    if filename in db_file_malware_dict:
        malware = db_file_malware_dict[filename]
        total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                             malware.get_total_executed_instructions())]
        outfile.write(str(malware) + '\n\n')
    if filename in file_corrupted_processes_dict:
        for malware in file_corrupted_processes_dict[filename]:
            total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                 malware.get_total_executed_instructions())]
            outfile.write(str(malware) + '\n\n')
    outfile.write('\nFinal instruction count: \n' + str(total_instruction_accumulator))


def clean_log(filename, dir_unpacked_path):
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')


def final_output(dir_project_path, filenames, db_file_malware_dict, file_corrupted_processes_dict):
    res_file = open(dir_project_path + 'resfile.txt', 'w')
    for filename in filenames:
        filename = filename[:-9]
        total_instruction_accumulator = [0, 0, 0, 0]
        res_file.write('File name: ' + filename + '\n')
        if filename in db_file_malware_dict:
            entry = db_file_malware_dict[filename]
            total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                 entry.get_total_executed_instructions())]
        if filename in file_corrupted_processes_dict:
            for entry in file_corrupted_processes_dict[filename]:
                total_instruction_accumulator = [sum(x) for x in zip(total_instruction_accumulator,
                                                                     entry.get_total_executed_instructions())]
        res_file.write('Final instruction count: \n' + str(total_instruction_accumulator))
        res_file.write('\n\n')


def update_dictionaries(pid, process_dict, proc_name, inverted_process_dict):
    if pid in process_dict:
        if proc_name in process_dict[pid]:
            process_dict[pid][proc_name] += 1
        else:
            process_dict[pid][proc_name] = 1
    else:
        process_dict[pid] = {}
        process_dict[pid][proc_name] = 1

    # the same values will also be added to the inverted dictionary
    if proc_name in inverted_process_dict:
        if pid in inverted_process_dict[proc_name]:
            inverted_process_dict[proc_name][pid] += 1
        else:
            inverted_process_dict[proc_name][pid] = 1
    else:
        inverted_process_dict[proc_name] = {}
        inverted_process_dict[proc_name][pid] = 1
