import os
import ast
from collections import defaultdict

dir_convert_path = '/home/yogaub/projects/seminar/converted/'

scsi_id = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
bios_id = "HARDWARE\\Description\\System"
empty_list = 'Final instruction count: 	[0, 0, 0, 0]'
dir_resfile_path = '/home/yogaub/Desktop/resfile.txt'


def fill_dicts(filenames, filename_scsi_dict, filename_bios_dict):
    for filename in filenames:
        with open(dir_convert_path + filename) as c_file:
            for line in c_file:
                if scsi_id in line:
                    filename_scsi_dict[filename] += 1
                elif bios_id in line:
                    filename_bios_dict[filename] += 1
    print len(filename_scsi_dict)
    print len(filename_bios_dict)


def acquire_conditions(filenames, term_sleep_dict, instrction_dict):
    next_file_name = True
    next_values = False
    with open(dir_resfile_path, 'r') as resfile:
        last_file_name = ''
        for line in resfile:
            line = line.strip()
            if not line:
                next_file_name = True
                continue
            if next_file_name:
                filename = line.split()[2]
                last_file_name = filename + '_c.txt'
                next_file_name = False
                next_values = True
                continue
            if next_values:
                if line != empty_list and last_file_name in filenames:
                    values = line.split('\t')[1].replace('[', '').replace(']', '').replace(',', '').split()
                    instrction_dict[last_file_name] = int(values[3])
                    values = next(resfile).split('\t')
                    terminating = ast.literal_eval(values[1].strip())
                    sleeping = ast.literal_eval(values[3].strip())
                    if sleeping:
                        term_sleep_dict[last_file_name] = 'Sleep'
                    elif terminating:
                        term_sleep_dict[last_file_name] = 'Termination'

                next_values = False
                continue


def main():
    filename_scsi_dict = defaultdict(int)
    filename_bios_dict = defaultdict(int)
    term_sleep_dict = {}
    instruction_dict = {}
    filenames = sorted(os.listdir(dir_convert_path))
    fill_dicts(filenames, filename_scsi_dict, filename_bios_dict)
    acquire_conditions(filenames, term_sleep_dict, instruction_dict)
    avg_inst = 0.0
    number = 0.0
    for filename in filenames:
        scsi_count = filename_scsi_dict.get(filename, 0)
        bios_count = filename_bios_dict.get(filename, 0)
        condition = term_sleep_dict.get(filename, 'None')
        instructions = instruction_dict.get(filename, 0)
        if scsi_count or bios_count:
            avg_inst += instructions
            number += 1
            print filename, scsi_count, bios_count, condition, instructions
    avg_inst = avg_inst / number
    print 'Average number of instructions: ', avg_inst
if __name__ == '__main__':
    main()
