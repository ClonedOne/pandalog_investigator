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
filename = 'File name:'
proc_name = 'Process name:'
proc_pid = 'Process ID:'
proc_orig = 'Process origin:'
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


# String used by detection modules
tags_reg_key = {
    'tag_scsi0_key': 'HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0',
    'tag_system_bios': 'HARDWARE\\Description\\System'
}
