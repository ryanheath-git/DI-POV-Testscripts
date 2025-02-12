import json
import pathlib
import unittest
import re
import sys

from repository import const
from repository.view import View
from repository import file_info_dict_template as fi
from conf.json_config_parser import JSONConfigParser
import warnings
from repository import factory

sys.path.append('../')

cfg = JSONConfigParser()
cfg.read_file(pathlib.Path('resources/test_config.json'))

# Get values from our config json file
default_api_key = cfg.get('virustotal', 'api_key')


class MyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings(action="ignore",
                                message="unclosed",
                                category=ResourceWarning)

    def tearDown(self) -> None:
        warnings.filterwarnings(action="ignore",
                                message="unclosed",
                                category=ResourceWarning)

    def test_malwarebazaar_view1(self):
        with pathlib.Path('resources/mb_file_infos.json').open('r') as jsonfile:
            js = json.load(jsonfile)

        list_of_file_info = js['mb_data']

        mbv = View(list_of_file_info)
        mbv.filter_on_first_seen(on_or_after='2022-05-05 00:00:00')

        hashes = mbv.hashes()
        self.assertEqual(hashes[0], '110a91b180bc3421d6c10d8dccd371994872e48a2414d12cf5c9dc0f15f1ee1f')
        self.assertEqual(hashes[1], 'e2cc138b0051fc6d2dce76941e2190d964c51754dac13705f63dad2941ccbba7')
        self.assertEqual(hashes[2], '4230d52f1dc1a49fd9660931806ce700ca50a0c163fae4171ffb71a2f3ab6325')
        self.assertEqual(hashes[3], 'dc3ff238364d0e6bc07b0024d5239020a364bc9c54b1a2ee078655ec55be792e')
        self.assertEqual(hashes[4], '6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202')
        print(mbv)

        name = mbv.get_file_name('e2cc138b0051fc6d2dce76941e2190d964c51754dac13705f63dad2941ccbba7')
        self.assertEqual(name, '7b7328a020bf16f8a3915f1a0b4e7ecb.exe')
        print(name)

        mbv.revert()

        mbv.filter_on_file_size(byte_size=500000)
        hashes = mbv.hashes()
        self.assertEqual(hashes[0], '110a91b180bc3421d6c10d8dccd371994872e48a2414d12cf5c9dc0f15f1ee1f')
        self.assertEqual(hashes[1], 'e2cc138b0051fc6d2dce76941e2190d964c51754dac13705f63dad2941ccbba7')
        self.assertEqual(hashes[2], 'dc3ff238364d0e6bc07b0024d5239020a364bc9c54b1a2ee078655ec55be792e')
        self.assertEqual(hashes[3], '6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202')
        self.assertEqual(hashes[4], '076737e5e088fe2883053ab51e675838921161f78ba8ae35421b61afbd5b2193')
        print(mbv)

    def test_vt_view1(self):
        query = 'type:pe p:0 AND NOT tag:"corrupt" size:1mb-'
        numfiles = 5
        vts = factory.create_search_by_id(const.VIRUSTOTAL_IDENTIFIER, default_api_key)
        vtv = vts.search_by_query(query, numfiles)
        hashes = vtv.hashes()

        fn = vtv.get_file_name(hashes[0])
        self.assertEqual(fn, not None)

    def test_vt_view_iterable(self):
        query = '3b12f391ce4a8edc951563ab412f154ce24597d206921f706c00ba0a6702a16d ' \
                'e2cc138b0051fc6d2dce76941e2190d964c51754dac13705f63dad2941ccbba7 ' \
                '3d3354c801cb7dba3d987ef2635568f85ac31c9b0bd6c6b8ace94ac96027fb79'
        numfiles = 5
        vts = factory.create_search_by_id(const.VIRUSTOTAL3_IDENTIFIER, default_api_key)
        vtv = vts.search_by_query(query, numfiles)

        query_items = query.split(' ')
        self.assertTrue(len(vtv))
        for (file_info, q) in zip(vtv, query_items):
            self.assertEqual(q, file_info[fi.SHA256_HASH_KEY])
            print(file_info)


if __name__ == '__main__':
    unittest.main()
