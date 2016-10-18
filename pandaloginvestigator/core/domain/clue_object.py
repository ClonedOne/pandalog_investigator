import logging


logger = logging.getLogger(__name__)


class Clue:

    def __init__(self, file_name):
        self.file_name = file_name
        self.opened_keys = {}
        self.queried_key_values = {}
        self.dangerous_instructions = {}

    # Setter Methods

    def add_opened_key(self, malware, tag_key, counter=None):
        tags_occurrencies = self.opened_keys.get(malware, {})
        if counter:
            tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + counter
        else:
            tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + 1
        self.opened_keys[malware] = tags_occurrencies

    def add_queried_key_value(self, malware, tag_value, counter=None):
        tags_occurrencies = self.queried_key_values.get(malware, {})
        if counter:
            tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + counter
        else:
            tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + 1
        self.queried_key_values[malware] = tags_occurrencies

    def add_dangerous_instructions(self, malware, tag_inst, counter=None):
        tags_occurrencies = self.dangerous_instructions.get(malware, {})
        if counter:
            tags_occurrencies[tag_inst] = tags_occurrencies.get(tag_inst, 0) + counter
        else:
            tags_occurrencies[tag_inst] = tags_occurrencies.get(tag_inst, 0) + 1
        self.dangerous_instructions[malware] = tags_occurrencies

    # Getter Methods

    def get_filename(self):
        return self.file_name

    def get_opened_keys(self):
        return self.opened_keys

    def get_queries_key_values(self):
        return self.queried_key_values

    def get_dangerous_instructions(self):
        return self.dangerous_instructions
