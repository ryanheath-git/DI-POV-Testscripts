import pathlib
import json

"""
Mimic sone of the functionality of ConfigParser.  Used to work with two level deep JSON files (section, keys, values)
"""


class JSONConfigParser:
    def __init__(self):
        """
        Intended as a very rudimentary JSON - ConfigParser-like helper
        """
        self.__json = {}

    def read_string(self, json_string: str):
        self.__json = json.load(json_string)

    def read_file(self, json_file: pathlib.Path):
        with json_file.open('r') as jsonfile:
            self.__json = json.load(jsonfile)

    def write_file(self, json_file: pathlib.Path):
        with json_file.open('w') as jsonfile:
            json.dumps(self.__json, jsonfile)  # Writing to the file

    def get(self, section, key):
        return self.__json[section][key]

    def set(self, section, key, value):
        self.__json[section][key] = value
