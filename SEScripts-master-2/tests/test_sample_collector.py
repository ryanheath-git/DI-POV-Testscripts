import unittest
from unittest import mock
import sys
import logging
import pathlib
import shutil
from datetime import date


sys.path.append('../')
import sample_collector as sc

DATASET_NAME = "test_dataset"

from conf.json_config_parser import JSONConfigParser
cfg = JSONConfigParser()
cfg.read_file(pathlib.Path('resources/test_config.json'))

# Get values from our config json file
api_key = cfg.get('virustotal', 'api_key')
base_collection_folder = cfg.get('downloader', 'collection_folder')
base_test_folder = cfg.get('downloader', 'test_folder')

#TODO Search for a PDF with 1d+ - if nothing returned what doe SC do? - Fail gracefully

class SampleCollectorTestCase(unittest.TestCase):

    @mock.patch('builtins.input')
    def test_sample_collector_main(self, mock_input):
        sys.argv.append('-a')
        sys.argv.append(api_key)
        sys.argv.append('-t')
        sys.argv.append(base_test_folder)
        sys.argv.append('-o')
        sys.argv.append(base_collection_folder)
        #collection name, dataset name, interactive mode (y/n), file type (0,1,2...)
        mock_input.side_effect = ['unit_test_coll', 'unit_test_defaults', '', '', '', '', '0']
        sc.main()
        self.assertTrue(True)

    def test_sample_collector1(self):
        dc = sc.DownloadCallback(10, "Testing")
        fdate = date.today().strftime('%Y-%m-%d')
        search = f'fs:{fdate}+ type:pe p:60+ AND NOT tag:"corrupt" size:1mb-'
        maxfiles = 10

        collection_folder = pathlib.Path(base_collection_folder) / 'test_sample_collector1'
        sc.sample_collector(DATASET_NAME, api_key, search, maxfiles,
                            pathlib.Path(base_test_folder),
                            collection_folder,
                            dc)

        num = len(list((collection_folder / DATASET_NAME).glob('*')))
        self.assertEqual(num, maxfiles)  # NOTE that there is no real way to make this test definitive -
        # the query could in fact return less than the 10 files we are looking for if DI "misses" something
        shutil.rmtree(collection_folder)

    def test_sample_collector_MB_check(self):
        dc = sc.DownloadCallback(25, "Testing")
        search = 'type:pe p:60+ size:1mb-'
        maxfiles = 25

        collection_folder = pathlib.Path(base_collection_folder) / 'test_sample_collector1'
        sc.sample_collector(DATASET_NAME, api_key, search, maxfiles,
                            pathlib.Path(base_test_folder),
                            collection_folder,
                            dc,
                            double_check=True)

        num = len(list((collection_folder / DATASET_NAME).glob('*')))
        self.assertTrue(num > 0)  # NOTE that there is no real way to make this test definitive, as there's no guarantee that MB will have any of the files
        shutil.rmtree(collection_folder)

    def test_sample_collector_no_detections(self):

        dc = sc.DownloadCallback(10, "Testing")
        fdate = date.today().strftime('%Y-%m-%d')
        search = f'fs:{fdate}+ type:pe p:0 AND NOT tag:"corrupt" size:1mb-'
        maxfiles = 10

        collection_folder = pathlib.Path(base_collection_folder) / 'test_sample_collector_no_detections'
        res = sc.sample_collector(DATASET_NAME, api_key, search, maxfiles,
                                  pathlib.Path(base_test_folder),
                                  collection_folder,
                                  dc)

        self.assertFalse(res)  # NOTE that there is no real way to make this test definitive -
        # the query could in fact return a positive verdict on a file with p:0
        if res:  # if we somehow did download something in a collection, clean it up
            shutil.rmtree(collection_folder)

    def test_sample_collector_nothing_found_to_test(self):

        dc = sc.DownloadCallback(2, "Testing")
        fdate = date.today().strftime('%Y-%m-%d')
        search = f'fs:{fdate}+ type:pdf p:65+ size:1mb-'
        maxfiles = 2

        collection_folder = pathlib.Path(base_collection_folder) / 'test_sample_collector_no_detections'
        res = sc.sample_collector(DATASET_NAME, api_key, search, maxfiles,
                                  pathlib.Path(base_test_folder),
                                  collection_folder,
                                  dc)

        self.assertFalse(res)  # NOTE that there is no real way to make this test definitive -
        # the query could in fact return a positive verdict on a file with p:0
        if res:  # if we somehow did download something in a collection, clean it up
            shutil.rmtree(collection_folder)


if __name__ == '__main__':
    unittest.main()
