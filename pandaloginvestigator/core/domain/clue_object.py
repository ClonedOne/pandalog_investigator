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

    # Adder Methods

    def add_opened_key(self, process, tag_key, counter=None):
        tags_occurrencies = self.opened_keys.get(process, {})
        if counter:
            tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + counter
        else:
            tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + 1
        self.opened_keys[process] = tags_occurrencies

    def add_queried_key_value(self, process, tag_value, counter=None):
        tags_occurrencies = self.queried_values.get(process, {})
        if counter:
            tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + counter
        else:
            tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + 1
        self.queried_values[process] = tags_occurrencies

    def add_dangerous_instructions(self, process, tag_inst, counter=None):
        tags_occurrencies = self.red_pills.get(process, {})
        if counter:
            tags_occurrencies[tag_inst] = tags_occurrencies.get(tag_inst, 0) + counter
        else:
            tags_occurrencies[tag_inst] = tags_occurrencies.get(tag_inst, 0) + 1
        self.red_pills[process] = tags_occurrencies

    # Setter Methods

    def set_opened_keys(self, opened_keys):
        self.opened_keys = opened_keys

    def set_queried_key_values(self, queried_key_values):
        self.queried_values = queried_key_values

    def set_dangerous_instructions(self, dangerous_instructions):
        self.red_pills = dangerous_instructions

    # Getter Methods

    def get_filename(self):
        return self.sample_uuid

    def get_opened_keys(self):
        return self.opened_keys

    def get_queries_key_values(self):
        return self.queried_values

    def get_dangerous_instructions(self):
        return self.red_pills

    def get_processes(self):
        processes = set(self.opened_keys.keys())
        processes |= set(self.queried_values.keys())
        processes |= set(self.red_pills.keys())
        return processes

    def get_everything_proc(self, process):
        res_list = []
        if self.opened_keys.get(process, None):
            res_list.append(self.opened_keys.get(process, None))
        if self.queried_values.get(process, None):
            res_list.append(self.queried_values.get(process, None))
        if self.red_pills.get(process, None):
            res_list.append(self.red_pills.get(process, None))
        return res_list

    # Remover Methods

    def remove_process(self, process):
        self.opened_keys.pop(process, None)
        self.queried_values.pop(process, None)
        self.red_pills.pop(process, None)