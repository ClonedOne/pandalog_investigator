import sqlite3

# malware process names are the first 14 characters of the md5
# the file name is actually the uuid

dir_malware_db = '/home/yogaub/projects/seminar/database/'
db_name = 'panda.db'
table_name = 'samples'
column1 = 'uuid'
column2 = 'filename'
column3 = 'md5'

def acquire_malware_file_dict():
    conn = sqlite3.connect(dir_malware_db + db_name)
    c = conn.cursor()
    big_file_malware_dict = {}

    c.execute('SELECT {col1},{col2} FROM {tn}'. format(tn=table_name, col1=column1, col2=column3))
    all_rows = c.fetchall()
    for row in all_rows:
        big_file_malware_dict[row[0]] = row[1][:14]

    conn.close()
    return big_file_malware_dict

