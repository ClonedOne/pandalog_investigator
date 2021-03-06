"""
This module contains fixed string parameters used by different modules inside the application.
"""


# File extensions
ext_investigator_clue = '_ss.txt'
ext_pandalog_file = '.plog'


# Paths relevant to the application.
dir_unpacked_path = 'dir_unpacked'
dir_translated_path = 'dir_translated'
dir_results_path = 'dir_results'
dir_analyzed_path = 'dir_analyzed'
dir_clues_path = 'dir_clues'

# Strings used to identify section of interest in panda log files.
tag_context_switch = u'new_pid,'
tag_termination = u'nt_terminate_process'
tag_process_creation = u'nt_create_user_process'
tag_write_memory = u'nt_write_virtual_memory'
tag_read_memory = u'nt_read_virtual_memory'
tag_write_file = u'nt_write_file'
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
dangerous_instruction = 'Dangerous instruction:'
original_mal = 'Original malware:'
suspect_ind = 'Suspect index:'
out_terminating = 'Terminating all:'
out_sleeping = 'Sleeping all:'
out_crashing = 'Crashing all:'
out_raising_error = 'Raising hard error all:'
out_writes_file = 'Writes files:'
out_final = 'Final instruction count:'
syscall_final = 'Final system call count:'
last_inst = 'Last starting instruction:'
exec_inst = 'Instruction executed:'
text_sleep = 'NtDelayExecution occurrences:'
text_spec_status = 'Special status conditions:'
text_crash = 'Crashing'
text_raise_err = 'Raising hard error'
text_written_file = 'Written files'
text_spawned = 'Spawned processes:'
text_terminated = 'Terminated processes:'
text_written = 'Memory written processes:'
text_executed = 'Instructions executed by all pids:'


# Strings used in clues files
current_process = 'Current process'
current_pid = 'PID'
parent_pid = 'PPID'
instruction_mnemonic = 'Instruction mnemonic'
instruction_operands = 'Instruction operands'
instruction_size = 'Instruction size'
instruction_bytes = 'Instruction bytes'

# Strings used in graph modules
target_i = 'instructions'
target_s = 'syscalls'

# System calls used to access registry keys
tag_open_key = 'nt_open_key'
tag_open_key_ex = 'nt_open_key_ex'
tag_access_key = ['nt_open_key', 'nt_create_key']
tag_query_key = 'nt_query_value_key'

# Particularly dangerous instruction tags
tag_dangerous = ('oversize', 'int1')

