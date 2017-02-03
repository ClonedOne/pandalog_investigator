from unittest import TestCase
from pandaloginvestigator.core.utils import utils


class TestStripFilenameExt(TestCase):
    def setUp(self):
        self.totest = utils.strip_filename_ext
        self.file_names_with_extension = ['0000c18e-a947-42ea-abb2-234ea18facdc.txz.plog',
                                          '0a1a1a77-d4f1-43e0-bc14-4f34f7d96820.txz.plog']
        self.file_names_without_extension = ['0000c18e-a947-42ea-abb2-234ea18facdc',
                                             '0a1a1a77-d4f1-43e0-bc14-4f34f7d96820']
        self.file_names_mixed_extension = ['0000c18e-a947-42ea-abb2-234ea18facdc.txz.plog',
                                           '0a1a1a77-d4f1-43e0-bc14-4f34f7d96820']

    def test_strip_filename_ext(self):
        self.assertListEqual(self.totest(self.file_names_with_extension), self.file_names_without_extension)

    def test_strip_filename_ext_fail(self):
        self.assertFalse(
            self.assertListEqual(self.totest(self.file_names_with_extension), self.file_names_without_extension))
