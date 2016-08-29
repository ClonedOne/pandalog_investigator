import os
import time
import utils
import worker_syscall_counter
from multiprocessing import Pool
from pprint import pprint


dir_project_path = '/home/yogaub/projects/seminar/'
dir_malware_db = '/home/yogaub/projects/seminar/database'
dir_resfile_path = '/home/yogaub/Desktop/resfile.txt'
dir_sys_call_table = '/home/yogaub/projects/seminar/'
dir_results = '/home/yogaub/projects/seminar/results/'
dir_analyzed_logs = '/home/yogaub/projects/seminar/analyzed_logs/'
waiting_syscalls = ('NtWaitForSingleObject', 'NtWaitForMultipleObjects', 'NtDelayExecution')


def out_on_file(syscall_freq, filename_total_syscall, total_without_wait):
    with open(dir_results + 'syscall_count.txt', 'w') as out_file:
        out_file.write('System calls occurrences:\n')
        for syscall in syscall_freq:
            out_file.write(syscall + '\t' + str(syscall_freq[syscall]) + '\n')
        out_file.write('\nTotal system calls by log file:\n')
        for filename in filename_total_syscall:
            out_file.write(filename + '\t' + str(filename_total_syscall[filename]) + '\n')
        out_file.write('\nTotal system calls by log file without waiting calls:\n')
        for filename in total_without_wait:
            out_file.write(filename + '\t' + str(total_without_wait[filename]) + '\n')
        total_stats = utils.compute_stats(filename_total_syscall)
        total_stats_without_wait = utils.compute_stats(total_without_wait)
        out_file.write('\nTotal stats:\n')
        out_file.write('Mean: ' + str(total_stats[0]) + '\tStandard deviation: ' +
                       str(total_stats[1]) + '\tVariance: ' + str(total_stats[2]))
        out_file.write('\nStats without waiting calls:\n')
        out_file.write('Mean: ' + str(total_stats_without_wait[0]) + '\tStandard deviation: ' +
                       str(total_stats_without_wait[1]) + '\tVariance: ' + str(total_stats_without_wait[2]))


def compute_total_without_wait(filename_syscall_dict):
    total_without_wait = {}
    for filename in filename_syscall_dict:
        tot = 0
        for syscall in filename_syscall_dict[filename]:
            if syscall not in waiting_syscalls:
                tot += filename_syscall_dict[filename][syscall]
        if tot:
            total_without_wait[filename] = tot
    return total_without_wait


def compute_syscall_freq(filename_syscall_dict):
    syscal_freq = {}
    for filename in filename_syscall_dict:
        for syscall in filename_syscall_dict[filename]:
            syscal_freq[syscall] = syscal_freq.get(syscall, 0) + filename_syscall_dict[filename][syscall]
    return syscal_freq


def compute_filename_total_syscall(filename_syscall_dict):
    filename_total_syscall = {}
    for filename in filename_syscall_dict:
        tot = 0
        for syscall in filename_syscall_dict[filename]:
            tot += filename_syscall_dict[filename][syscall]
        if tot:
            filename_total_syscall[filename] = tot
    return filename_total_syscall


def update_results(results, filename_syscall_dict):
    for sub_res in results:
        filename_syscall_dict.update(sub_res)


def acquire_sys_calls():
    sys_call_dict = {}
    with open(dir_sys_call_table + 'sys_tab.txt') as tabfile:
        for line in tabfile:
            line = line.split()
            if len(line) > 1:
                sys_call_dict[int(line[1], 16)] = line[0]
    return sys_call_dict


def acquire_filename_malware():
    filename_malware_dict = {}
    filenames = sorted(os.listdir(dir_analyzed_logs))
    for filename in filenames:
        filename_malware_dict[filename[:-6]] = []
        with open(dir_analyzed_logs + filename) as an_file:
            for line in an_file:
                if 'Malware name:' in line:
                    last_mal = line.split(':')[1].strip()
                if 'Malware pid:' in line:
                    pid = int(line.split()[2].strip())
                    filename_malware_dict[filename[:-6]].append((last_mal, pid))
    return filename_malware_dict


def main():
    filename_syscall_dict = {}
    sys_call_dict = acquire_sys_calls()
    filename_malware_dict = acquire_filename_malware()
    filenames = filename_malware_dict.keys()
    j = 0
    file_names_0 = []
    file_names_1 = []
    file_names_2 = []
    file_names_3 = []
    for filename in filenames:
        if j % 4 == 0:
            file_names_0.append(filename)
        elif j % 4 == 1:
            file_names_1.append(filename)
        elif j % 4 == 2:
            file_names_2.append(filename)
        else:
            file_names_3.append(filename)
        j += 1
        if j == 40:
            break
    t1 = time.time()
    pool = Pool(processes=4)
    results = pool.map(worker_syscall_counter.work, [(0, file_names_0, sys_call_dict, filename_malware_dict),
                                                     (1, file_names_1, sys_call_dict, filename_malware_dict),
                                                     (2, file_names_2, sys_call_dict, filename_malware_dict),
                                                     (3, file_names_3, sys_call_dict, filename_malware_dict)])
    t2 = time.time()
    update_results(results, filename_syscall_dict)
    print "Multicore time", t2-t1
    pprint(len(filename_syscall_dict))
    syscall_freq = compute_syscall_freq(filename_syscall_dict)
    filename_total_syscall = compute_filename_total_syscall(filename_syscall_dict)
    total_without_wait = compute_total_without_wait(filename_syscall_dict)
    out_on_file(syscall_freq, filename_total_syscall, total_without_wait)


if __name__ == '__main__':
    main()
