

# Use the provided table of system calls to generate a system call number -> system call name dictionary.
# Reference system is Windows 7 SP 01.
def get_syscalls():
    syscall_dict = {}
    with open('syscalls.tsv') as syscall_file:
        for line in syscall_file:
            line = line.split('\t')
            syscall_dict[int(line[0])] = line[1]
    return syscall_dict


