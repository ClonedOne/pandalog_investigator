# This module contains fixed string parameters used by different modules
# inside the application.


# Paths relevant to the application.
dir_unpacked_path = 'created_dirs/dir_unpacked_path'
dir_translated_path = 'created_dirs/dir_translated_path'
dir_results_path = 'created_dirs/dir_results_path'
dir_analyzed_path = 'created_dirs/dir_analyzed_path'
dir_syscall_path = 'created_dirs/dir_syscall_path'


# Strings used to identify section of interest in log files.
context_switch = u'new_pid,'
instruction_termination = u'nt_terminate_process'
instruction_process_creation = u'nt_create_user_process'
instruction_write_memory = u'nt_write_virtual_memory'
instruction_read_memory = u'nt_read_virtual_memory'
instruction_sleep = u'(num=98)'
instruction_raise_error = u'(num=272)'
error_manager = u'WerFault.exe'
system_call_tag = u'nt_any_syscall (num='
