
class CorruptedProcess:
    """
        This class represents a single corrupted process. A process is considered corrupted if:
         * is the original software samples being analyzed - FROM_DB
         * is directly created by a corrupted process - CREATED 
         * it's memory is written by a corrupted process - WRITTEN
    """

    FROM_DB = 'database'
    CREATED = 'created'
    WRITTEN = 'mem_written'
    origins = [FROM_DB, CREATED, WRITTEN]

    def __init__(self, process_info, origin, parent_process):
        """
        Creates a corrupted process object.
        
        :param process_info: tuple composed by (process name, pid)
        :param origin: the origin of this process [FROM_DB, CREATED, WRITTEN]
        :param parent_process: the parent process information (itself if origin is FROM_DB)
        """
        self.process_info = process_info
        self.instruction_executed = 0
        self.last_starting_instruction = 0
        # Terminated, created and written processes consists of tuples (new process info, path to the executable)
        self.terminated_processes = set()
        self.created_processes = set()
        self.written_memory = set()
        self.written_file = set()
        self.sleep = 0
        self.crashed = False
        self.error = False
        self.terminated = False
        self.origin = origin
        self.parent = parent_process

    def __eq__(self, other):
        return isinstance(other, self.__class__) and other.process_info == self.process_info

    def __hash__(self):
        return hash(self.process_info)


