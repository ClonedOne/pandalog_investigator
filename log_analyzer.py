import os
import pprint
import sys

dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'
new_proc = 'new_pid,'
termination_instruction = 'num=369)'


def main():
    for i in sorted(os.listdir(dir_unpacked_path)):
        sys.stdout = sys.__stdout__
        print 'analyzing file: ' + i
        process_dict = {}
        inverted_process_dict = {}
        termination_list = []
        with open(dir_unpacked_path + i, "r") as logfile:
            for line in logfile:
                # check if the line contains the system call for termination NtTerminateProcess
                if termination_instruction in line:
                    termination_list.append(line.strip())
                    print line
                # for each log line check if it the spawn of a new process
                words = line.split()
                if new_proc in words:
                    # if it is save in the process dictionary the pid and process name
                    pid = int(words[4].replace(',', ''))
                    proc_name = words[5].replace(')', '')
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

        sys.stdout = open(dir_analyzed_logs+i+'_a.txt', 'w')
        pprint.pprint(process_dict)
        pprint.pprint(inverted_process_dict)
        pprint.pprint(termination_list)


if __name__ == '__main__':
    main()
