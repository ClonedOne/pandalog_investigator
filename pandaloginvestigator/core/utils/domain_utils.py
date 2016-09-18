from pandaloginvestigator.core.domain.malware_object import Malware


# This module handles utility methods which are inherently related to the
# domain of the application.

# Utility method to initialize a new malware object given the relative process
# name and file name. Checks whether the new process would be the db_malware
# or a corrupted process.
def initialize_malware_object(filename, malware_name, db_file_malware_dict, file_corrupted_processes_dict, from_db=False):
    malware = Malware(malware_name)
    if from_db:
        db_file_malware_dict[filename] = malware
        return malware
    if filename in file_corrupted_processes_dict:
        file_corrupted_processes_dict[filename].append(malware)
    else:
        file_corrupted_processes_dict[filename] = []
        file_corrupted_processes_dict[filename].append(malware)
    return malware
