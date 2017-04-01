class CorruptedProcess:
    """
    This class represents a single corrupted process. A process is considered corrupted if:
     * is the original software samples being analyzed - FROM_DB
     * is directly created by a corrupted process - CREATED 
     * it's memory is written by a corrupted process - WRITTEN
    """

    def __init__(self, process_info, origin, parent_process):
        """
        Creates a corrupted process object.
        
        :param process_info: tuple composed by (process name, pid)
        :param origin: the origin of this process [FROM_DB, CREATED, WRITTEN]
        :param parent_process: the parent process information (itself if origin is FROM_DB)
        """
        self.process_info = process_info
        self.instruction_executed = 0
        self.starting_instruction = 0
        self.terminated_processes = []
        # Created processes consists of tuples (new process info, path to the executable)
        self.created_processes = []
        self.written_memory = []
        self.written_file = []
        self.sleep = 0
        self.crashing = False
        self.error = False
        self.origin = origin
        self.parent = parent_process

    def __eq__(self, other):
        return isinstance(other, self.__class__) and other.process_info == self.process_info

    def __hash__(self):
        return hash(self.process_info)
