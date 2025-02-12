import shutil
import unittest
import sys
import os
import pathlib
from repository.downloader import FileDownloadHandler, EncryptedZipDownloadHandler
from conf.json_config_parser import JSONConfigParser

sys.path.append('../')
import test_detection as td
from unittest.mock import patch


class TestDetectionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = JSONConfigParser()
        self.cfg.read_file(pathlib.Path('resources/test_config.json'))

        # Get values from our config json file
        self.default_api_key = self.cfg.get('virustotal', 'api_key')
        self.test_folder = self.cfg.get('downloader', 'test_folder')
        self.fdh = FileDownloadHandler(self.test_folder, 'malware')

    def tearDown(self) -> None:
        shutil.rmtree(self.fdh.download_folder)

    def test_test_detection_main(self):
        cmd_line = f'test_detections.py -a {self.default_api_key} -n 20 ' \
                   f'fs:1d+ type:pe p:35+ size:1mb-'
        args = cmd_line.split(' ')
        args.extend(["-t", str(self.fdh.download_folder)]) # since the filepath has a space in it, this has to be done
        # separately, otherwise it gets split into parts
        with patch.object(sys, 'argv', args):
            td.main()
        self.assertTrue(True)  # add assertion here

    def test_test_detection_main_no_results(self):
        cmd_line = f'test_detections.py -a {self.default_api_key} -n 2 ' \
                   f'fs:1d+ type:pdf p:65+'
        args = cmd_line.split(' ')
        args.extend(["-t", str(self.fdh.download_folder)]) # since the filepath has a space in it, this has to be done
        # separately, otherwise it gets split into parts

        with patch.object(sys, 'argv', args):
            td.main()

        self.assertTrue(True)  # add assertion here

    def test_test_detection_with_positive_detections(self):
        positive, negative = td.test_detection(self.default_api_key, 'fs:2022-07-07+ type:pe p:55+', 5, self.fdh)
        self.assertTrue(
            len(positive) > 0)  # there's not a way to assure that these are absolutely true, but, most of the time it should be
        self.assertEqual(len(negative), 0)

    def test_test_detection_with_negative_detections(self):
        positive, negative = td.test_detection(self.default_api_key, 'fs:2022-07-07+ type:pe p:0', 5, self.fdh)

        self.assertTrue(
            len(negative) > 0)  # there's not a way to assure that these are absolutely true, but, most of the time it should be
        self.assertEqual(len(positive), 0)


if __name__ == '__main__':
    unittest.main()
