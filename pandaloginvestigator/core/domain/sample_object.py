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
        self.active_corrupted_process = None

    def __eq__(self, other):
        return isinstance(other, self.__class__) and other.sample_uuid == self.sample_uuid

    def __hash__(self):
        return hash(self.sample_uuid)
