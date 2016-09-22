from pandaloginvestigator.core.domain.malware_object import Malware
from pandaloginvestigator.core.domain.suspect import Suspect


# This module handles utility methods which are inherently related to the
# domain of the application. Therefore this module has explicit knowledge
# of domain's structure.


# Utilities related to Malware class.

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


# Returns a string representation of the specified malware object.
def repr_malware(malware):
    string_spawned = '\nSpawned processes: new pid | process name | instruction | executable path\n'
    string_terminated = '\nTerminated processes: terminated pid | terminated process name | instruction\n'
    string_written = '\nMemory written: written pid | written process name | instruction\n'
    string_sleep = '\nNtDelayExecution called: occurrences\n'
    string_executed = '\nInstructions executed by all pids: DB | created | memory written | total\n'
    string_crash_missing_dll = '\nCrashing | missing a dll:\n'

    result = 'Malware name: ' + malware.name + '\n'
    for i in malware.pid_list:
        result += '\nMalware pid: ' + str(i) + '\t' + malware.origin[i] + '\n' \
                  + 'Last starting instruction: ' + str(malware.starting_instruction[i]) + '\n' \
                  + 'Instruction executed: ' + str(malware.instruction_executed[i]) + '\n'

        result += string_spawned
        for entry in malware.spawned_processes[i]:
            for sub_entry in entry:
                result += str(sub_entry) + '\t'
            result += '\n'

        result += string_terminated
        for entry in malware.terminated_processes[i]:
            for sub_entry in entry:
                result += str(sub_entry) + '\t'
            result += '\n'

        result += string_written
        for entry in malware.written_memory[i]:
            for sub_entry in entry:
                result += str(sub_entry) + '\t'
            result += '\n'

        result += string_sleep
        result += str(malware.sleep[i])
        result += string_crash_missing_dll
        result += str(malware.crashing[i]) + '\t' + str(malware.error[i])
        result += '\n'

    result += string_executed
    executed = malware.get_total_executed_instructions()
    result += str(executed[0]) + '\t' + str(executed[1]) + '\t' + str(executed[2]) + '\t' + str(executed[3]) + '\n'

    return result


# Returns a list of the processes names and ids of the specified malware as
# a string.
def repr_malware_processes(malware):
    result = ''
    pid_list = malware.pid_list
    name = malware.name
    for pid in pid_list:
        parent = malware.get_parent_of(pid)
        if not parent:
            parent = (name, pid)
        result = '\t\t{:15s} {:10d} {:25s} by: {:15s} {:10d}\n'.format(name, pid, malware.origin[pid], parent[0], parent[1])
    return result


# Utilities related to system calls.

# Use the provided table of system calls to generate a system call number -> system call name dictionary.
# Reference system is Windows 7 SP 01.
def get_syscalls():
    syscall_dict = {}
    with open('syscalls.tsv') as syscall_file:
        for line in syscall_file:
            line = line.split('\t')
            syscall_dict[int(line[0])] = line[1].strip()
    return syscall_dict


# Utilities related to Suspect class.

# Provide a string representation of the suspect object.
def repr_suspect(suspect):
    result = 'Filename: ' + suspect.file_name + '\n'
    for tag in suspect.reg_dict:
        result += '\t' + tag + ':\n'
        for details in suspect.reg_dict[tag]:
            result += '\t\t' + details[0] + '\t' + details[1] + '\t' + details[2] + '\n'
    return result
