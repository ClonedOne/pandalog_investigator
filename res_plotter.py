import matplotlib.pyplot as plt
import numpy


dir_resfile_path = '/home/yogaub/Desktop/resfile.txt'
dir_accumulationfile_path = '/home/yogaub/Desktop/accfile.txt'
dir_analyzed_path = '/home/yogaub/Desktop/analyzed_logs/'
empty_list = '[0, 0, 0, 0]'

totals_dict = {}
from_db_dict = {}
created_dict = {}
written_dict = {}

file_list = []
next_file_name = True
next_values = False


def compute_stats(chosen_dict):
    print 'computing stats'
    values = numpy.array(chosen_dict.values())
    mean = values.mean()
    standard_deviation = values.std()
    variance = values.var()
    return mean, standard_deviation, variance


def plot_data(chosen_dict, stats, color, shape, title, log=False):
    print 'plotting data'
    accumulation_list = []
    ranges = []
    standard_deviation = stats[1]
    std_multiplier = 0.0
    i = 0
    values = numpy.array(sorted(chosen_dict.values()))
    # ranges_length = values.max()
    # print ranges_length / (standard_deviation*0.1)
    for value in values:
        while value >= standard_deviation * std_multiplier:
            accumulation_list.append(0)
            std_multiplier += 0.1
            ranges.append(standard_deviation * std_multiplier)
            i += 1
        accumulation_list[i-1] += 1

    accumulation_list = numpy.array(accumulation_list)
    ranges = numpy.array(ranges)
    print accumulation_list
    print ranges

    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    if log:
        # ax.set_xscale('log')
        ax.set_yscale('log')
    ax.plot(ranges, accumulation_list, color+shape, markersize=8)
    ax.plot(ranges, accumulation_list, color, linewidth=2)
    plt.title(title)
    plt.xlabel("Value range in standard deviations")
    plt.ylabel("Frequency")
    plt.show()


def invert_dictionary(chosen_dict):
    inverted_dict = {}
    for malware_name, count in chosen_dict.iteritems():
        if count in inverted_dict:
            inverted_dict[count].append(malware_name)
        else:
            inverted_dict[count] = []
            inverted_dict[count].append(malware_name)
    return inverted_dict


def print_results(totals_dict, inverted_totals, stats):
    print 'printing data on file'
    with open(dir_accumulationfile_path, 'w') as accfile:
        for entry in totals_dict:
            accfile.write(str(entry) + '\t' + str(totals_dict[entry]) + '\n')
        accfile.write('\n')
        for key in sorted(inverted_totals.keys()):
            accfile.write(str(key) + '\t' + str(inverted_totals[key]) + '\n')
        accfile.write('\n')
        accfile.write('Mean: ' + str(stats[0]) + '\n')
        accfile.write('Standard Deviation: ' + str(stats[1]) + '\n')
        accfile.write('Variance: ' + str(stats[2]) + '\n')


def accumulate_data():
    print 'accumulating data'
    global next_file_name, next_values, file_list, totals_dict
    skip = False
    with open(dir_resfile_path, 'r') as resfile:
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
                skip = True
                continue
            if skip:
                next_values = True
                skip = False
                continue
            if next_values:
                if line != empty_list:
                    values = line.replace('[', '').replace(']', '').replace(',', '').split()
                    if int(values[0]) == 0:
                        print 'PANIC NO DB'
                    if int(values[3]) == 0:
                        print 'PANIC NO TOT'
                    from_db_dict[last_file_name] = int(values[0])
                    if int(values[1]) > 0:
                        created_dict[last_file_name] = int(values[1])
                    if int(values[2]) > 0:
                        written_dict[last_file_name] = int(values[2])
                    totals_dict[last_file_name] = int(values[3])
                next_values = False
                continue


def prune_data(chosen_dict, threshold_number):
    values = sorted(chosen_dict.values())
    length = len(values)
    eliminate_vals = []
    eliminate_keys = []
    for i in range(length):
        if i < threshold_number or (length -1) - i < threshold_number:
            eliminate_vals.append(values[i])
    for key, value in chosen_dict.iteritems():
        if value in eliminate_vals:
            eliminate_keys.append(key)
    for key in eliminate_keys:
        chosen_dict.pop(key)


def do_stuff(chosen_dict, color, shape, title, total=False, log=False):
    if total:
        print len(chosen_dict)
        inverted_totals = invert_dictionary(chosen_dict)
        stats = compute_stats(chosen_dict)
        print stats
        compute_number_of_terminated(chosen_dict, stats[0]*0.1)
        print_results(chosen_dict, inverted_totals, stats)
        plot_data(chosen_dict, stats, color, shape, title, log)
    else:
        print len(chosen_dict)
        stats = compute_stats(chosen_dict)
        print stats
        plot_data(chosen_dict, stats, color, shape, title, log)


def check_self_termination(filename):
    with open(dir_analyzed_path + filename + '_a.txt', 'r') as a_log:
        last_mal = ''
        pids = []
        terminated_pids = []
        for line in a_log:
            if 'Malware name:' in line:
                last_mal = line.split()[2].strip()
            if 'Malware pid:' in line:
                pid = line.split()[2].strip()
                pids.append((last_mal, pid))
            if 'Terminated processes:' in line:
                line = a_log.next()
                while line.strip():
                    mal_name = line.split('\t')[1].strip()
                    mal_pid = line.split('\t')[0].strip()
                    terminated_pids.append((mal_name, mal_pid))
                    line = a_log.next()
    equal = True
    for entry in pids:
        if entry not in terminated_pids:
            equal = False
    # if filename == '0cd4c283-1765-42a2-b911-deb1497da527':
    #     print 'is 0cd4c283-1765-42a2-b911-deb1497da527'
    #     if equal:
            print 'is self terminating'
    return equal


def compute_number_of_terminated(chosen_dict, threshold):
    below_threshold = 0
    self_terminated = 0
    for filename, value in chosen_dict.iteritems():
        if value < threshold:
            below_threshold += 1
            if check_self_termination(filename):
                self_terminated += 1
    print below_threshold, self_terminated


def main():
    accumulate_data()

    do_stuff(totals_dict, 'b', 'H', 'Total', total=True)
    prune_data(totals_dict, 100)
    do_stuff(totals_dict, 'b', 'H', 'Total pruned')

    do_stuff(from_db_dict, 'g', 'o', 'Malware from database')
    prune_data(from_db_dict, 100)
    do_stuff(from_db_dict, 'g', 'o', 'Malware from database pruned')

    do_stuff(created_dict, 'r', 'o', 'Created processes')
    prune_data(created_dict, 10)
    do_stuff(created_dict, 'r', 'o', 'Created processes pruned')

    do_stuff(written_dict, 'y', 'o', 'Memory written processes')
    prune_data(written_dict, 10)
    do_stuff(written_dict, 'y', 'o', 'Memory written processes pruned')


if __name__ == '__main__':
    main()




