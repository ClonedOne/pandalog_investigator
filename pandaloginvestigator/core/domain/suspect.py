import logging


logger = logging.getLogger(__name__)


# In the following methods the 'malware' object is represented as a
# process name, process id pair.
class Suspect:

    def __init__(self, file_name):
        self.file_name = file_name
        self.opened_keys = {}
        self.queried_key_values = {}

    # Setter Methods

    def add_opened_key(self, malware, tag_key):
        tags_occurrencies = self.opened_keys.get(malware, {})
        tags_occurrencies[tag_key] = tags_occurrencies.get(tag_key, 0) + 1
        self.opened_keys[malware] = tags_occurrencies

    def add_queried_key_value(self, malware, tag_value):
        tags_occurrencies = self.queried_key_values.get(malware, {})
        tags_occurrencies[tag_value] = tags_occurrencies.get(tag_value, 0) + 1
        self.queried_key_values[malware] = tags_occurrencies

    # Getter Methods

    def get_filename(self):
        return self.file_name

    def get_opened_keys(self):
        return self.opened_keys

    def get_queries_key_values(self):
        return self.queried_key_values
