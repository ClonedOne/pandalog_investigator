from volatility.plugins.overlays.windows.win7_sp01_x86_syscalls import syscalls


# Use the 'volatility' syscall plugin to obtain a dictionary of the available syscalls under Windows 7 SP 1.
def get_syscalls():
    syscall_dict = {}
    nt_table = syscalls[0]
    gdi_table = syscalls[1]
    nt_displace = 0
    gdi_displace = 4096
    for syscall_num in range(len(nt_table)):
        syscall_dict[syscall_num + nt_displace] = nt_table[syscall_num]
    for syscall_num in range(len(gdi_table)):
        syscall_dict[syscall_num + gdi_displace] = gdi_table[syscall_num]
    return syscall_dict
