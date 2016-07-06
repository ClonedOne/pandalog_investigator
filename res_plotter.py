import matplotlib.pyplot as plt
import numpy
import math

dir_resfile_path = '/home/yogaub/Desktop/resfile.txt'
dir_accumulationfile_path = '/home/yogaub/Desktop/accfile.txt'
malware_dict = {}
file_list = []
next_file_name = True
next_malware_name = False
inverted_malware_dict = {}
mean = 0
standard_deviation = 0
variance = 0
billion = 1000000000


def compute_stats():
    print 'computing stats'
    global mean, standard_deviation, variance
    values = numpy.array(malware_dict.values())
    mean = values.mean()
    standard_deviation = values.std()
    variance = values.var()


def plot_data():
    print 'plotting data'
    accumulation_list = []
    ranges = []
    std_multiplier = 0
    #std_multiplier = 0.0
    i = 0
    values = numpy.array(malware_dict.values())
    print len(values)
    values = sorted(values)
    #print values
    for value in values:
        if value > standard_deviation * std_multiplier:
            accumulation_list.append(0)
            std_multiplier += 1
            #std_multiplier += 0.5
            ranges.append(standard_deviation * std_multiplier)
            i += 1
        else:
            accumulation_list[std_multiplier-1] += 1
            #accumulation_list[i-1] += 1

    accumulation_list = numpy.array(accumulation_list)
    ranges = numpy.array(ranges)
    print accumulation_list
    print ranges

    #histogram = plt.figure()
    plt.plot(ranges, accumulation_list, "H", markersize=12)
    plt.plot(ranges, accumulation_list, "b", linewidth=2)
    plt.title("Instruction executed")
    plt.xlabel("Value range")
    plt.ylabel("Frequency")
    plt.xticks(ranges)
    #plt.yticks(accumulation_list)
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


def print_results():
    print 'printing data on file'
    #numpy_arr = numpy.ndarray(malware_dict)
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


if __name__ == '__main__':
    main()




