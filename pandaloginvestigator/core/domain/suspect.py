from pandaloginvestigator.core.utils import string_utils
import logging


logger = logging.getLogger(__name__)
tags_reg_key = string_utils.tags_reg_key


class Suspect:

    def __init__(self, file_name):
        self.file_name = file_name
        self.reg_dict = {}
        for tag in tags_reg_key:
            self.reg_dict[tag] = []

    def add_tag_occ(self, tag, instr_num):
        if tag in self.reg_dict:
            self.reg_dict[tag].append(instr_num)
            return 1
        return -1
