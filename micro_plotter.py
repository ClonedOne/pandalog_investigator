import matplotlib.pyplot as plt
import numpy
import utils


dir_stats_count = '/home/yogaub/projects/seminar/results/'
stats_file_name = 'syscall_stats.txt'


def plot_data(chosen_dict, stats, color, shape, title):
    print 'plotting data'
    accumulation_list = []
    ranges = []
    standard_deviation = stats[1]
    std_multiplier = 0.0
    i = 0
    values = numpy.array(sorted(chosen_dict.values()))

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
    ax.plot(ranges, accumulation_list, color+shape, markersize=8)
    ax.plot(ranges, accumulation_list, color, linewidth=2)
    plt.title(title)
    plt.xlabel("Value range")
    plt.ylabel("Frequency")
    plt.show()



def gather_data(total=True):
    stats_dict = {}
    with open(dir_stats_count + stats_file_name) as stats_file:
        section = 0
        for line in stats_file:
            if not line.strip():
                stats_file.next()
                section += 1
            elif total and section == 1:
                line = line.split('\t')
                stats_dict[line[0].strip()] = int(line[1].strip())
            elif section == 2:
                line = line.split('\t')
                stats_dict[line[0].strip()] = int(line[1].strip())

    return stats_dict


def main():
    total_dict = gather_data()
    total_stats = utils.compute_stats(total_dict)
    reduced_dict = gather_data(False)
    reduced_stats = utils.compute_stats(reduced_dict)
    plot_data(total_dict, total_stats, 'b', 'o', 'Total system calls')
    plot_data(reduced_dict, reduced_stats, 'g', 'o', 'System calls excluding waiting')

    utils.prune_data(total_dict, 200)
    print len(total_dict)
    total_stats_pruned = utils.compute_stats(total_dict)
    utils.prune_data(reduced_dict,2100)
    print len(reduced_dict)
    reduced_stats_pruned = utils.compute_stats(reduced_dict)
    plot_data(total_dict, total_stats_pruned, 'b', 'o', 'Total system calls pruned')
    plot_data(reduced_dict, reduced_stats_pruned, 'g', 'o', 'System calls excluding waiting pruned')


if __name__ == '__main__':
    main()