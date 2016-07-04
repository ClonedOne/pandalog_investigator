import os
import subprocess
import pprint
import sys
import db_manager
from malware_object import Malware

dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'
dir_malware_db = '/home/yogaub/projects/seminar/database'

malware_list = ['16223bcdeecb43', 'c2556a4275cfa4', 'c34498f94110af', 'c3d6b7f9684101', '4830e9a6906469',
                'e1f2df81e63964', '69974072a4743d']
unpack_command = './pandalog_reader'
new_proc = 'new_pid,'
termination_instruction = 'num=369)'
termination_dict = {}
malwares = {}


def unpack_log(filename):
    print 'unpacking: ' + filename
    return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + filename + " > " +
                                  dir_unpacked_path + filename + ".txt", shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)


def is_malware(new_malware_name, new_filename, new_pid, new_current_instruction):
    cur_malware = None
    # check if the malware name found is already in the dictionary
    for filename, malware in malwares.iteritems():
        if malware.get_name() == new_malware_name:
            # the malware is already present in the dictionary
            if filename != new_filename:
                print 'ERROR the same malware appears in two different files'
                return -1
            cur_malware = malware
    if cur_malware is None:
        new_malware = Malware(new_malware_name, new_pid)
        cur_malware = new_malware
        malwares[new_filename] = new_malware

    position = cur_malware.get_pid_position(new_pid)
    # if the position is -1 it means the new_pid is not already in the malware pid list
    if position == -1:
        cur_malware.add_pid(new_pid)
        position = cur_malware.get_pid_position(new_pid)

    # once the current malware has been identified, update its current instruction value
    cur_malware.update_starting_instruction(position, new_current_instruction)
    return 1


def analyze_log(filename, malware_name):
    print 'analyzing: ' + filename
    process_dict = {}
    inverted_process_dict = {}
    termination_list = []
    # malware_running = False

    with open(dir_unpacked_path + filename + '.txt', 'r') as logfile:
        for line in logfile:
            # check if the line contains the system call for termination NtTerminateProcess
            if termination_instruction in line:
                termination_list.append(line.strip())
                print line
            words = line.split()

            # for each log line check if it logs a context switch
            if new_proc in words:
                pid = int(words[4].replace(',', ''))
                proc_name = words[5].replace(')', '')
                current_instruction = (words[0].split('='))[1]

                # check if the process name is in the known malware list
                if proc_name == malware_name:
                    is_malware(proc_name, filename, pid, current_instruction)

                # since it is a context switch save in the process dictionary the pid and process name
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

    sys.stdout = open(dir_analyzed_logs + filename + '_a.txt', 'w')
    pprint.pprint(process_dict)
    pprint.pprint(inverted_process_dict)
    pprint.pprint(termination_list)
    if filename in malwares:
        pprint.pprint(malwares[filename])
    sys.stdout = sys.__stdout__


def clean_log(filename):
    print 'deleting: ' + filename + '.txt'
    os.remove(dir_unpacked_path + filename + '.txt')


def main():
    j = 0
    os.chdir(dir_panda_path)
    big_file_malware_dict = db_manager.acquire_malware_file_dict()
    for filename in sorted(os.listdir(dir_pandalogs_path)):
        # each file has to be unpacked using the PANDA tool
        unpack_log(filename)
        # analyze the unpacked log file
        analyze_log(filename, big_file_malware_dict[filename[:-9]])
        # since the size of the unpacked logs will engulf the disk, delete the file after the process
        # clean_log(filename)

        j += 1
        if j == 10:
            exit()


if __name__ == '__main__':
    main()
