import unittest
import pathlib
import json
from repository import file_info_dict_template


class FileInfoDictTestCases(unittest.TestCase):

    def test_file_info_dict(self):
        with pathlib.Path('resources/mb_file_infos.json').open('r') as jsonfile:
            js = json.load(jsonfile)
        file_info_dict_from_mb = js['mb_data'][0]

        new_dict = file_info_dict_template.new_file_info_dict(
            '110a91b180bc3421d6c10d8dccd371994872e48a2414d12cf5c9dc0f15f1ee1f',
            file_type='exe',
            file_name='Invoice.exe'
        )

        self.assertEqual(file_info_dict_from_mb[file_info_dict_template.FILE_NAME_KEY],
                         new_dict[file_info_dict_template.FILE_NAME_KEY])  # add assertion here


if __name__ == '__main__':
    unittest.main()
