from pandaloginvestigator.core.domain.corrupted_process_object import CorruptedProcess


class Sample:
    """
    This class represents a single software sample analyzed using PANDA. Therefore it corresponds to a single pandalog
    file.
    """

    def __init__(self, sample_uuid, malware_name):
        """
        Creates a new sample object with an empty set of corrupted processes and no currently active processes.
        The corrupted_processes dictionary maps (process name, process id) tuples with the related CorruptedProcess
        objects.
        
        :param sample_uuid: the md5 hash of the file
        :param malware_name: name of the malware sample obtained from the database
        """
        self.sample_uuid = sample_uuid
        self.malware_name = malware_name
        self.corrupted_processes = {}
        self.activity_ranges = []
        self.active_corrupted_process = None

    def __eq__(self, other):
        return isinstance(other, self.__class__) and other.sample_uuid == self.sample_uuid

    def __hash__(self):
        return hash(self.sample_uuid)

    """
    Auxiliary methods to get global information on corrupted processes 
    """

    def sleep_all(self):
        """
        Checks if all the corrupted processes have called sleep
        
        :return: boolean 
        """

        if len(self.corrupted_processes) == 0:
            return False

        for process_info, process in self.corrupted_processes.items():
            if not process.sleep:
                return False
        return True

    def terminate_all(self):
        """
        Checks if all the corrupted processes have terminated
        
        :return: boolean
        """

        if len(self.corrupted_processes) == 0:
            return False

        for process_info, process in self.corrupted_processes.items():
            if not process.terminated:
                return False
        return True

    def crash_all(self):
        """
        Checks if all the corrupted processes have crashed
        
        :return: boolean
        """

        if len(self.corrupted_processes) == 0:
            return False

        for process_info, process in self.corrupted_processes.items():
            if not process.crashed:
                return False
        return True

    def error_all(self):
        """
        Checks if all the corrupted processes have raised errors
        
        :return: boolean
        """

        if len(self.corrupted_processes) == 0:
            return False

        for process_info, process in self.corrupted_processes.items():
            if not process.error:
                return False
        return True

    def write_file(self):
        """
        Checks if at least one corrupted process has written a file
        
        :return: boolean 
        """

        if len(self.corrupted_processes) == 0:
            return False

        for process_info, process in self.corrupted_processes.items():
            if len(process.written_file) > 0:
                return True
        return False

    def total_instruction(self):
        """
        Returns the total count of instructions executed by corrupted processes as a list:
         * instruction count from processes whose origin is 'databse'
         * instruction count from processes whose origin is 'created'
         * instruction count from processes whose origin is 'written'
         * total instruction count 
        
        :return: total count of instruction
        """

        total = [0, 0, 0, 0]
        origins = CorruptedProcess.origins
        origins_rng = range(len(origins))

        for process_info, process in self.corrupted_processes.items():
            total[3] += process.instruction_executed
            for i in origins_rng:
                if process.origin == origins[i]:
                    total[i] += process.instruction_executed

        return total

    def total_syscalls(self):
        """
        Returns the total count of system calls executed by corrupted processes as a list:
         * system calls count from processes whose origin is 'databse'
         * system calls count from processes whose origin is 'created'
         * system calls count from processes whose origin is 'written'
         * total system calls count 
        
        :return: total count of system calls
        """

        total = [0, 0, 0, 0]
        origins = CorruptedProcess.origins
        origins_rng = range(len(origins))

        for process_info, process in self.corrupted_processes.items():
            total[3] += process.syscalls_executed
            for i in origins_rng:
                if process.origin == origins[i]:
                    total[i] += process.syscalls_executed

        return total

    def total_activity_ranges(self):
        """
        Produces a single list comprehending all the instruction ranges where a corrupted process was active. 
        
        :return: 
        """

        activities = {}

        for process_info, process in self.corrupted_processes.items():
            for activity in process.activity_ranges:
                activities[activity[0]] = activity[1]

        self.activity_ranges = [(start_inst, end_inst) for start_inst, end_inst in sorted(activities.items())]
        self.active_corrupted_process = None




class ReducedSample:
    """
    This class corresponds to a smaller and simplified version of the Sample object containing only aggregated values.
    Its purpose is to reduce memory usage during the analysis process.
    Since it is just a representation object, its constructor requires a full Sample object.
    """

    def __init__(self, sample):
        """
        From a given Sample object constructs a new ReducedSample object containing only aggregated Sample data.
        
        :param sample: original Sample object 
        """
        self.sample_uuid = sample.sample_uuid
        self.malware_name = sample.malware_name
        self.total_instruction = sample.total_instruction()
        self.total_syscalls = sample.total_syscalls()
        self.sleep_all = sample.sleep_all()
        self.terminate_all = sample.terminate_all()
        self.crash_all = sample.crash_all()
        self.error_all = sample.error_all()
        self.write_file = sample.write_file()

        self.corrupted_processes = []
        for process_info, process in sample.corrupted_processes.items():
            self.corrupted_processes.append((
                process_info[0],
                process_info[1],
                process.origin,
                process.parent[0],
                process.parent[1]
            ))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and other.sample_uuid == self.sample_uuid

    def __hash__(self):
        return hash(self.sample_uuid)
