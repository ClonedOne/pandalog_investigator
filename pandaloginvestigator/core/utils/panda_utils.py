import subprocess


# Unpack the specified log file using the PANDA 'pandalog_reader' utility.
# The content of the log will be saved in a temporary file with the same name.
def unpack_log(dir_panda_path, filename, dir_pandalogs_path, dir_unpacked_path):
    unpack_command = '/pandalog_reader'
    reduced_filename = filename[:-9]
    return_code = subprocess.call(dir_panda_path + unpack_command + " " + dir_pandalogs_path + '/' + filename + " > " +
                                  dir_unpacked_path + '/' + reduced_filename, shell=True)
    if return_code != 0:
        print 'return code: ' + str(return_code)
