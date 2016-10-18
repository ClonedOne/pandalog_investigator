import logging


logger = logging.getLogger(__name__)


class Clue:

    def __init__(self, file_name):
        self.file_name = file_name
        self.opened_keys = {}
        self.queried_key_values = {}
        self.dangerous_instructions = {}

    # Adder Methods

    def add_opened_key(self, process, tag_key, counter=None):
        tags_occurrencies = self.opened_keys.get(process, {})
        if counter:
            tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + counter
        else:
            tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + 1
        self.opened_keys[process] = tags_occurrencies

    def add_queried_key_value(self, process, tag_value, counter=None):
        tags_occurrencies = self.queried_key_values.get(process, {})
        if counter:
            tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + counter
        else:
            tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + 1
        self.queried_key_values[process] = tags_occurrencies

    def add_dangerous_instructions(self, process, tag_inst, counter=None):
        tags_occurrencies = self.dangerous_instructions.get(process, {})
        if counter:
            tags_occurrencies[tag_inst] = tags_occurrencies.get(tag_inst, 0) + counter
        else:
            tags_occurrencies[tag_inst] = tags_occurrencies.get(tag_inst, 0) + 1
        self.dangerous_instructions[process] = tags_occurrencies

    # Setter Methods

    def set_opened_keys(self, opened_keys):
        self.opened_keys = opened_keys

    def set_queried_key_values(self, queried_key_values):
        self.queried_key_values = queried_key_values

    def set_dangerous_instructions(self, dangerous_instructions):
        self.dangerous_instructions = dangerous_instructions

    # Getter Methods

    def get_filename(self):
        return self.file_name

    def get_opened_keys(self):
        return self.opened_keys

    def get_queries_key_values(self):
        return self.queried_key_values

    def get_dangerous_instructions(self):
        return self.dangerous_instructions

    def get_processes(self):
        processes = set(self.opened_keys.keys())
        processes = processes | set(self.queried_key_values.keys())
        processes = processes | set(self.dangerous_instructions.keys())
        return processes

    def get_everything_proc(self, process):
        res_list = []
        if self.opened_keys.get(process, None):
            res_list.append(self.opened_keys.get(process, None))
        if self.queried_key_values.get(process, None):
            res_list.append(self.queried_key_values.get(process, None))
        if self.dangerous_instructions.get(process, None):
            res_list.append(self.dangerous_instructions.get(process, None))
        return res_list

    # Remover Methods

    def remove_process(self, process):
        self.opened_keys.pop(process, None)
        self.queried_key_values.pop(process, None)
        self.dangerous_instructions.pop(process, None)