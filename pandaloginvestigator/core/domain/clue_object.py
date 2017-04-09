import logging


logger = logging.getLogger(__name__)


class Clue:
    """
    This class represents the aggregation of clues regarding sandbox evasion discovered while analyzing a sample.
    """

    # Low instruction executed threshold
    FIRST_POPULATION = 80000000

    def __init__(self, sample_uuid):
        self.sample_uuid = sample_uuid
        self.opened_keys = {}
        self.queried_values = {}
        self.red_pills = {}
        self.create_write_process = False
        self.low_instruction = False
        self.termination = False
        self.write_file = False
        self.sleep = False
