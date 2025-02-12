import unittest
import os
import pathlib
import time

from datetime import date
from repository import const
from repository.malwarebazaar.mb_search import MalwareBazaarSearch
from repository.vt3.vt3_search import VT3Search

from repository import factory

from conf.json_config_parser import JSONConfigParser

cfg = JSONConfigParser()
cfg.read_file(pathlib.Path('resources/test_config.json'))

# Get values from our config json file
default_api_key = cfg.get('virustotal', 'api_key')


class SearchTestCases(unittest.TestCase):

    def test_search_by_factory(self):
        limit = 25
        mbs = factory.create_search_by_id(const.MALWAREBAZAAR_IDENTIFIER)
        mbv = mbs.search_by_query('fs:2022-05-05+ type:exe size:1mb-', limit)
        hashes = mbv.hashes()

        self.assertTrue(len(hashes) > 5)  # there's not a definitive way to do this search and return exactly 5 results,
        # but would expect at least 5 of type exe

        for file_hash in hashes:
            size = mbv.get_file_size(file_hash)
            self.assertTrue(size < 1000000)

    def test_malwarebazaar_search_by_query(self):
        numfiles = 5
        mbv = MalwareBazaarSearch().search_by_query('fs:2022-05-05+ type:pe size:1mb-', numfiles)
        hashes = mbv.hashes()

        self.assertTrue(len(hashes) > 0)

    def test_malwarebazaar_search_by_hash(self):
        mbv = MalwareBazaarSearch().search_by_hash('110a91b180bc3421d6c10d8dccd371994872e48a2414d12cf5c9dc0f15f1ee1f')
        hashes = mbv.hashes()
        self.assertEqual(hashes[0], '110a91b180bc3421d6c10d8dccd371994872e48a2414d12cf5c9dc0f15f1ee1f')

    def test_malwarebazaar_search_by_hashes(self):
        hashes = ["2cf1d1bd9f44d17acc08e7a9be9f9d6c7ac63bbf5194e33390f0e00a803d41d8",
                  "3b12f391ce4a8edc951563ab412f154ce24597d206921f706c00ba0a6702a16d",  # this doesn't exist
                  "69d0885e1490db820cfa69e85ee79f0fa96375c65b32606c3fa2a6edfe19cf1a",
                  "0aa2a490888e688686a9d839412a913757b2dc64a1c8fdea7686f398fba64be2",
                  "6de97bfadfe7649dc49d618190ba4c8be5e6d5cb21b6ef2c6ef6e5f80cab00f0"
                  ]

        mbv = MalwareBazaarSearch().search_by_hashes(hashes, limit=2)
        hashes = mbv.hashes()
        self.assertTrue(len(hashes) == 2)  # should be limited to 2 results
        self.assertEqual(hashes[0], '2cf1d1bd9f44d17acc08e7a9be9f9d6c7ac63bbf5194e33390f0e00a803d41d8')
        self.assertEqual(hashes[1], '69d0885e1490db820cfa69e85ee79f0fa96375c65b32606c3fa2a6edfe19cf1a')

    def test_malwarebazaar_search_by_hashes_no_results(self):
        hashes = ['7bfefa8a9fe1352bf5a6a018a6356e321cbbdbc8f1871e43625f62ec28052c91',
                  'de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085',
                  '6a7093440420306cf7de53421a67af8a1094771e0aab9535acbd748d08ed766c',
                  '5a2b856dee75f4d88aef7ded47871be925ef8786f270b4117d75e0d4d8a05ea6',
                  '5c95c6b37ae2a9ba68c1a43172ab3cc0ead140d501c121e9d16f51baad853372',
                  '54282ec29d4993ed6e9972122cfbb70bba4898a21d527bd9e72a166d7ec2fdc0',
                  '63b02a3e8e7e049d1f29cd4cd79fe5c8905754da6c023df72aa5cca351d0d5c5',
                  'c6bdbb0243b81a042233636b5c13f247d7abc3d516d97a3bca478c473bea9dd7',
                  '20af03add533a6870d524a7c4753b42bfceb56cddd46016c051e23581ba743f8',
                  'c7e604d9be11d184c5af7681c2b54a449d75c010d7e1234712ab7ce74ffcc5d9']
        mbv = MalwareBazaarSearch().search_by_hashes(hashes, limit=2)
        self.assertTrue(mbv.empty())

    def test_malwarebazaar_search_by_hashes_speed_test(self):
        hashes = ['21285f6d8702236a5d8fad688ab0385e06fe0fe26493e19cbfab489340b897b1',
                  '074f995f2fa28d0d37d5e15025e5dba48e6c883dde43db78a49958837f02d90f',
                  'd67c9b134aee7dfb48b9c6de98d4c4bf5c5a1c428bce86484fcc6c732908c99f',
                  '38fbf4ef63938c61701107b226bef84d19a357b215830ce660101cfe6f59e75c',
                  '8a1902d9c0dbe388b28ef5a9c8ec4c0f1802fc6ccd43471ea337dcb3d71c81d4',
                  '125a63ab3d6386246a317e3bc8babe73791f90d8cc1fb0e3c43b05928eae7cb5',
                  'e4fd14f4b3549e87e04a3c052cc47846bf4b2ba430cb5f4b554cf0b17429c80c',
                  'a58f7ca70595d7712b2ee497067698b69e1f6eb8173fe898fa1874ce57ad39fd',
                  '27789fe43e5b48b450aba03add7a9e4a323a85bedc95eac9fab651c85045264f',
                  '4e691a1e0f5a5ae464e64348bace0d5e5f1bf70f38eb353fc163d9abeda0a980',
                  '10572dc0a9857ed4dccfbdc00bcc50b6761e2cb1d8c3b0a0c291b798e2129968',
                  '9ae2e560480170f9f51889ec2bc03bb0b24d8313a401a8cfaa1800413d43ba46',
                  'c487b74c979bf5168a8801b81e3f110c65adec409973cf2ad965d7e66bb3df33',
                  'face066a155a17daff1b1b3763f1ee17f17447677cbb9cded3cd867c5edecb40',
                  'b9949e03b39983874549b98f9c1fa7378c2bf92afbab93cc316628b3ba83b94f',
                  'e795f31218fe0f27f982c4750b9cbb3400460233b66b5eb724085bb881cab3bc',
                  'c1439189bf8e92ec68670be37eba55d29cffbeba5cd8073aff0314f9dd8868a2',
                  'dc100a273ab33d5c80929e4acbd1efbc4565b5645ee6ad61900e622061bc3b2a',
                  '18c3d29d088477235cb4c08440259ce201b842dc4f58e49e121399b066be4d4e',
                  'c8ef7df613682412a29f9d0942f8ecbf2113976553a798a52705d5069bf2e28e',
                  '4e9b4ed5b34272696c249d4141c73441f5c5ba3148c710972726bba99ed1125c',
                  '9c627e04268f715f0675c9912b2f84a6696fc5376181a44517a82f403cc85766',
                  'fe15391608b0aed8a21dc50946718b06fc6bab27f2f2bf9d97d69d8882a5973b',
                  '66b675cc754e6bed36b15dd38f9e555edfcd4644c60366c0f7e03f82a4f11962',
                  '253876e1ac2b7cecbeb8f6b137215058eab10c144ea32d9d9a62887f785da3ac',
                  '7af13986b1bd05d3bba2ecbbb254039639098f51a368fcb8d261346f82df9bc6',
                  '3bb25e53dd67753296acd73d45cd09d890e484d841be611b0979040ba0a4788d',
                  '627fddb693b027c9fe8e084a38aa570b992287ba589ceed95413d808b5e54b50',
                  'd345a48336baf5628666374f407c48c082963bb333a90d39e3ccbe287a81545a',
                  '9280dfdfb310a1033c236ef9074ec14b76cd79db67b7cfaf154ac619a63cf7fe',
                  '193134b44ba9c7f488e0d68466c15eab1ad2db136972f079c3776d5614092581',
                  'd39c3748e219f7fa34d00ae460672b5139b9d071a3e93ff2a6f4b1a8405fa7c8',
                  '6b3a9965a5ca75c80af6c750138088e25d3b70177a5d87dd77799f332c0c7b3f',
                  '9e7d1e942346f53ab118bf116ef5609f28495a054bdcf1d8bb014b099383299f',
                  'eec6176659c47b0545550db4637b60a39aa6ed7203bc96609f6a6226d8992aa8',
                  '26128920b3c6ff310abc74397694f0d44fc728271530616108ba04a237479029',
                  'ace7c172137b290e1fcf56d6d09288d1d4ee8314437efc83d7c342d26836f297',
                  'a04581c6aff92bdda3feb705ce9e2e803ea5eacd7584b2d78457435b864c0360',
                  '2738a22fb21c6fc665fa2ab06cb15509dc261702993040d5747d484147f82137',
                  'ac4096129cf5a5e79c57965e6ba020b80d908764c4576bd8a6cbe9f8e6e2a860',
                  '079d3b3cf0106c0fcb817ae926fb90ba89b908440df1b4256d988b8c223b89f0',
                  'a19d997ec2685b0f6416250d6f6be69c92c31e3ed53f61c942525da8f844f880',
                  'bfac1bfcd1b3b0b7668d0d4bc05191c3f0fc9eab84cc458b3fb382c4fbcc5cae',
                  'e038146d4d2142fea6a0edce71085a246489dcbbbe634db1251425105c92b98a',
                  '6e5cdc4c4ec06e1e0bba6e31e55dfc3c32f988b5587fabd771150f87b72018f3',
                  '4aca43a5faaec3fb75b470f1327d069c7d17c656945e130cb6f057938a1d41b3',
                  '409b27ddd1f883a432b3a5e3eaeaaefd644dfdd1f952e46edc0c6ee4ebad59f4',
                  'f7a837d3a49e914ad647cd58231604c91f709b758c3deffc38659eb97529cae4',
                  '32414f6d470b9d0e606d8cb549b4457466c30834de0132f45137d4aa56b6af4f',
                  'e3a40607525551219edc7389b05dd636fb527adffdb62126fffe9a92dadf37f1']

        start = time.perf_counter()
        mbv = MalwareBazaarSearch().search_by_hashes(hashes, limit=10)
        duration = time.perf_counter() - start
        print(f'Search and download time: {duration}')

        self.assertTrue(True)

    def test_VT_search_by_hashes(self):
        hashes = ["2cf1d1bd9f44d17acc08e7a9be9f9d6c7ac63bbf5194e33390f0e00a803d41d8",
                  "3b12f391ce4a8edc951563ab412f154ce24597d206921f706c00aaaaaaaaaaaa",  # this doesn't exist
                  "69d0885e1490db820cfa69e85ee79f0fa96375c65b32606c3fa2a6edfe19cf1a",
                  "0aa2a490888e688686a9d839412a913757b2dc64a1c8fdea7686f398fba64be2",
                  "6de97bfadfe7649dc49d618190ba4c8be5e6d5cb21b6ef2c6ef6e5f80cab00f0"
                  ]

        vts = VT3Search(default_api_key).search_by_hashes(hashes, limit=2)
        hashes = vts.hashes()
        self.assertTrue(len(hashes) == 2)  # should be limited to 2 results
        self.assertEqual(hashes[0], '2cf1d1bd9f44d17acc08e7a9be9f9d6c7ac63bbf5194e33390f0e00a803d41d8')
        self.assertEqual(hashes[1], '69d0885e1490db820cfa69e85ee79f0fa96375c65b32606c3fa2a6edfe19cf1a')
        self.assertEqual(vts.get_file_name('2cf1d1bd9f44d17acc08e7a9be9f9d6c7ac63bbf5194e33390f0e00a803d41d8'),
                         '2cf1d1bd9f44d17acc08e7a9be9f9d6c7ac63bbf5194e33390f0e00a803d41d8')
        self.assertEqual(vts.get_file_name('69d0885e1490db820cfa69e85ee79f0fa96375c65b32606c3fa2a6edfe19cf1a'),
                         'DelayProm')

    def test_vt_search_by_query1(self):
        # search for one benign file
        fdate = date.today().strftime('%Y-%m-%d')
        query = f'fs:{fdate}+ type:pe p:0 AND NOT tag:"corrupt" size:1mb- microsoft:clean'
        numfiles = 1

        vts = VT3Search(default_api_key).search_by_query(query, numfiles)
        hashes = vts.hashes()

        self.assertEqual(numfiles, len(hashes))

    def test_vt_search_by_query2(self):
        # search for one, benign file, no first_seen... ask for specific file properties
        query = 'type:pe p:0 AND NOT tag:"corrupt" size:1mb-'
        numfiles = 5
        vtv = VT3Search(default_api_key).search_by_query(query, numfiles)
        hashes = vtv.hashes()
        self.assertEqual(numfiles, len(hashes))

        file_name = vtv.get_file_name(
            hashes[0])  # this cause the VTView to retrieve more info, becasue it has nothing on this hash yet
        first_seen = vtv.get_first_seen(hashes[0])
        self.assertTrue(file_name)

        first_seen = vtv.get_first_seen(
            hashes[1])  # this causes the VTView to retrieve more info, becasue it has nothing on this hash yet
        self.assertTrue(first_seen)

    def test_vt_larger_search_by_query(self):
        # tests the intelligence search functionality for retrieving multiple pages of files
        query = 'type:pe p:0 AND NOT tag:"corrupt" size:1mb-'
        numfiles = 50

        vtv = VT3Search(default_api_key).search_by_query(query, numfiles)
        hashes = vtv.hashes()

        self.assertEqual(numfiles, len(hashes))


if __name__ == '__main__':
    unittest.main()
