# This module contains fixed string parameters used by different modules
# inside the application.


# Paths relevant to the application.
dir_unpacked_path = 'created_dirs/dir_unpacked'
dir_translated_path = 'created_dirs/dir_translated'
dir_results_path = 'created_dirs/dir_results'
dir_analyzed_path = 'created_dirs/dir_analyzed'
dir_syscall_path = 'created_dirs/dir_syscall'


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
no_instructions = 'Final instruction count:  [0, 0, 0, 0]'
no_syscalls = 'Final system call count:     0'
filename = 'File name: '
instruction_final = 'Final instruction count: \t'
instruction_terminating = 'Terminating all: \t'
instruction_sleeping = 'Sleeping all: \t'
instruction_crashing = 'Crashing all: \t'
instruction_raising_error = 'Raising hard error all: \t'
syscall_final = 'Final system call count: \t'


# Strings used in plotting modules.
target_i = 'instructions'
target_s = 'syscalls'
