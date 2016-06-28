import os
import subprocess

dir_unpacked_path = '/home/yogaub/projects/seminar/unpacked_logs/'
dir_pandalogs_path = '/home/yogaub/projects/seminar/pandalogs/'
dir_panda_path = '/home/yogaub/projects/seminar/panda/qemu/panda'
unpack_command = './pandalog_reader'


def main():
    j = 0
    os.chdir(dir_panda_path)
    for i in sorted(os.listdir(dir_pandalogs_path)):
        print 'unpacking: ' + i
        return_code = subprocess.call(unpack_command + " " + dir_pandalogs_path + i + " > " +
                                      dir_unpacked_path + i + ".txt", shell=True)
        print return_code
        j += 1
        if j == 1000:
            exit()


if __name__ == '__main__':
    main()
