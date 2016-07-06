import matplotlib.pyplot as plt
import numpy

dir_resfile_path = '/home/yogaub/Desktop/resfile.txt'
dir_accumulationfile_path = '/home/yogaub/Desktop/accfile.txt'
dir_reduced_accumulationfile_path = '/home/yogaub/Desktop/accfile_red.txt'

malware_dict = {}
inverted_malware_dict = {}
mean = 0
standard_deviation = 0
variance = 0

file_list = []
next_file_name = True
next_malware_name = False

reduced_malware_dict = {}
reduced_inverted_malware_dict = {}
reduced_mean = 0
reduced_standard_deviation = 0
reduced_variance = 0


def reduce_data():
    global malware_dict, reduced_malware_dict, reduced_inverted_malware_dict
    threshold = standard_deviation * 0.5
    #threshold = mean
    for malware_name, value in malware_dict.iteritems():
        if value < threshold:
            reduced_malware_dict[malware_name] = value
            if value in reduced_inverted_malware_dict:
                reduced_inverted_malware_dict[value].append(malware_name)
            else:
                reduced_inverted_malware_dict[value] = []
                reduced_inverted_malware_dict[value].append(malware_name)
    #print len(reduced_malware_dict)


def compute_stats(reduced=False):
    print 'computing stats'
    if reduced:
        global reduced_mean, reduced_standard_deviation, reduced_variance
        values = numpy.array(reduced_malware_dict.values())
        reduced_mean = values.mean()
        reduced_standard_deviation = values.std()
        reduced_variance = values.var()
    else:
        global mean, standard_deviation, variance
        values = numpy.array(malware_dict.values())
        mean = values.mean()
        standard_deviation = values.std()
        variance = values.var()


def plot_data(reduced=False):
    print 'plotting data'
    accumulation_list = []
    ranges = []
    #std_multiplier = 0
    std_multiplier = 0.0
    i = 0
    if reduced:
        values = numpy.array(sorted(reduced_malware_dict.values()))
        for value in values:
            if value > reduced_standard_deviation * std_multiplier:
                accumulation_list.append(0)
                std_multiplier += 0.5
                ranges.append(reduced_standard_deviation * std_multiplier)
                i += 1
                accumulation_list[i - 1] += 1
            else:
                accumulation_list[i - 1] += 1
    else:
        values = numpy.array(sorted(malware_dict.values()))
        for value in values:
            if value > standard_deviation * std_multiplier:
                accumulation_list.append(0)
                #std_multiplier += 1
                std_multiplier += 0.5
                ranges.append(standard_deviation * std_multiplier)
                i += 1
                #accumulation_list[std_multiplier - 1] += 1
                accumulation_list[i-1] += 1
            else:
                #accumulation_list[std_multiplier-1] += 1
                accumulation_list[i-1] += 1

    accumulation_list = numpy.array(accumulation_list)
    ranges = numpy.array(ranges)
    print accumulation_list
    print ranges

    plt.plot(ranges, accumulation_list, "H", markersize=12)
    plt.plot(ranges, accumulation_list, "b", linewidth=2)
    plt.title("Instruction executed")
    plt.xlabel("Value range")
    plt.ylabel("Frequency")
    plt.xticks(ranges)
    plt.show()


def invert_dictionary():
    global malware_dict, inverted_malware_dict
    for malware_name, count in malware_dict.iteritems():
        if count in inverted_malware_dict:
            inverted_malware_dict[count].append(malware_name)
        else:
            inverted_malware_dict[count] = []
            inverted_malware_dict[count].append(malware_name)


def clean_zero_values():
    print 'cleaning zero values'
    global malware_dict
    temp_dict = {}
    for entry in malware_dict:
        if malware_dict[entry] != 0:
            temp_dict[entry] = malware_dict[entry]
    malware_dict = temp_dict


def print_results(reduced=False):
    print 'printing data on file'
    if reduced:
        with open(dir_reduced_accumulationfile_path, 'w') as accfile:
            for entry in reduced_malware_dict:
                accfile.write(str(entry) + '\t' + str(reduced_malware_dict[entry]) + '\n')
            accfile.write('\n')
            for key in sorted(reduced_inverted_malware_dict.keys()):
                accfile.write(str(key) + '\t' + str(reduced_inverted_malware_dict[key]) + '\n')
            accfile.write('\n')
            accfile.write('Mean: ' + str(reduced_mean) + '\n')
            accfile.write('Standard Deviation: ' + str(reduced_standard_deviation) + '\n')
            accfile.write('Variance: ' + str(reduced_variance) + '\n')

    else:
        with open(dir_accumulationfile_path, 'w') as accfile:
            for entry in malware_dict:
                accfile.write(str(entry) + '\t' + str(malware_dict[entry]) + '\n')
            accfile.write('\n')
            for key in sorted(inverted_malware_dict.keys()):
                accfile.write(str(key) + '\t' + str(inverted_malware_dict[key]) + '\n')
            accfile.write('\n')
            accfile.write('Mean: ' + str(mean) + '\n')
            accfile.write('Standard Deviation: ' + str(standard_deviation) + '\n')
            accfile.write('Variance: ' + str(variance) + '\n')


def accumulate_data():
    print 'accumulating data'
    global next_file_name, next_malware_name, file_list, malware_dict
    with open(dir_resfile_path, 'r') as resfile:
        last_malware_name = ''
        for line in resfile:

            if not line.strip():
                next_file_name = True
                continue

            line = line.strip()

            if next_file_name:
                filename = line
                if filename in file_list:
                    return
                file_list.append(filename)
                next_file_name = False
                next_malware_name = True
                continue

            if next_malware_name:
                last_malware_name = line.replace('-', '').strip()
                malware_dict[last_malware_name] = 0
                next_malware_name = False
                continue

            words = line.split('\t')
            #print words[2].split()[2]
            instruction_count = int(words[2].split()[2])
            malware_dict[last_malware_name] += instruction_count


def main():
    accumulate_data()
    clean_zero_values()
    invert_dictionary()
    compute_stats()
    print_results()
    plot_data()
    reduce_data()
    compute_stats(reduced=True)
    print_results(reduced=True)
    plot_data(reduced=True)

if __name__ == '__main__':
    main()




