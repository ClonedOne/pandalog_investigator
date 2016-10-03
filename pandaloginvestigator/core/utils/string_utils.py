# This module contains fixed string parameters used by different modules
# inside the application.


# Paths relevant to the application.
dir_unpacked_path = 'dir_unpacked'
dir_translated_path = 'dir_translated'
dir_results_path = 'dir_results'
dir_analyzed_path = 'dir_analyzed'
dir_syscall_path = 'dir_syscall'


# Strings used to identify section of interest in panda log files.
tag_context_switch = u'new_pid,'
tag_termination = u'nt_terminate_process'
tag_process_creation = u'nt_create_user_process'
tag_write_memory = u'nt_write_virtual_memory'
tag_read_memory = u'nt_read_virtual_memory'
tag_sleep = u'(num=98)'
tag_raise_error = u'(num=272)'
error_manager = u'WerFault.exe'
tag_system_call = u'nt_any_syscall (num='


# Strings related to output files.
no_instructions = 'Final instruction count:\t[0, 0, 0, 0]'
no_syscalls = 'Final system call count:\t0'
filename = 'File name:'
proc_name = 'Process name:'
proc_pid = 'Process ID:'
proc_orig = 'Process origin:'
opened = 'Opened key:'
queried = 'Queried value:'
instruction_terminating = 'Terminating all:'
instruction_sleeping = 'Sleeping all:'
instruction_crashing = 'Crashing all:'
instruction_raising_error = 'Raising hard error all:'
instruction_final = 'Final instruction count:'
syscall_final = 'Final system call count:'
last_inst = 'Last starting instruction:'
exec_inst = 'Instruction executed:'
text_sleep = 'NtDelayExecution occurrences:'
text_crash_missing_dll = 'Crashing | missing a dll:'
text_spawned = 'Spawned processes: new pid | process name | instruction | executable path'
text_terminated = 'Terminated processes: terminated pid | terminated process name | instruction'
text_written = 'Memory written: written pid | written process name | instruction'
text_executed = 'Instructions executed by all pids: DB | created | memory written | total'


# Strings used in plotting modules.
target_i = 'instructions'
target_s = 'syscalls'


# System calls used to access registry keys
tag_open_key = 'nt_open_key'
tag_query_key = 'nt_query_value_key'

# Interesting registry keys
tag_keys = [
    'HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0',
    'HARDWARE\\Description\\System',
    'HARDWARE\\ACPI\\DSDT\\VBOX__',
    'HARDWARE\\ACPI\\FADT\\VBOX__',
    'HARDWARE\\ACPI\\RSDT\\VBOX__',
    'SOFTWARE\\Oracle\\VirtualBox Guest Additions',
    'HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum'
]

# Values to be checked inside the keys
tag_values = ['SystemBiosDate', 'SystemBiosVersion', 'VideoBiosVersion', 'QEMU']
