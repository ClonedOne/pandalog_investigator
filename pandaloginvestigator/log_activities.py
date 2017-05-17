import jsonpickle
import os

"""
This is a temporary utility method to retrieve a list of activity session from each analysis log
"""

dir_analysis = '/home/yogaub/Documents/malwords_temp/invesigator_analysis'
dir_output = '/home/yogaub/Documents/malwords_temp/invesigator_analysis'
for report in os.listdir(dir_analysis):
    with open(os.path.join(dir_analysis, report), "r", encoding='utf-8', errors='replace') as sample_file:
        sample = jsonpickle.decode(sample_file.read(), keys=True)

        ranges = [(list(elem.values())[0]) for elem in sample['activity_ranges']]
        with open(os.path.join(dir_output, report[:-5]), 'w', encoding='utf-8') as out_file:
            for activity in ranges:
                out_file.write('{}\t{}\n'.format(activity[0], activity[1]))

