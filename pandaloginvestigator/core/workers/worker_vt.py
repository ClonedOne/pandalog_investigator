import logging
import time
import os

"""
Worker process in charge of analyzing VirusTotal results files.
"""

# Global Variables
logger = logging.getLogger(__name__)


def work(data_pack):
    """
    VirusTotal analysis worker main method. The data passed to each worker contains:
     * worker id - 0
     * list of file names to analyze - 1
     * path to the VirusTotal files - 2
     * path to the analyzed logs directory - 3
    
    :param data_pack: data needed by the worker 
    :return: 
    """

    j = 0.0
    starting_time = time.time()

    # Unpacking of the passed data
    worker_id = data_pack[0]
    file_names = data_pack[1]
    dir_vt_path = data_pack[2]
    dir_analyzed_logs = data_pack[3]

    total_vts = len(file_names)

    for file_name in file_names:

        j += 1
        logger.info('WorkerId {} {:.2%}'.format(str(worker_id), (j / total_vts)))


