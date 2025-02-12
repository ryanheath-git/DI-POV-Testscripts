import logging
import re
from abc import ABC, abstractmethod
from repository.view import View


def is_valid_search(search):
    """
    Does a rudimentary check to determine if search is a search that will be accepted.  Simply looks for keywords,
    but does not validate if the query will actually run.
    Args:
        search: a search query

    Returns: True, if a VT search, false is not

    """
    se = re.findall('fs:|first_seen:|type:|engines:|tag:|p:|positives:|ls:|name:', search)
    if not se:
        return False
    return True


class Search(ABC):
    def __init__(self):
        """
        This is a factory class for the creation of a View via a search method
        """
        pass

    @abstractmethod
    def search_by_query(self, search, limit: int) -> View:
        pass

    def search_by_hash(self, file_hash) -> View:
        """
        Helper method that simply calls search_by_hashes with a single element hash list
        Args:
            file_hash: a sha256 hash

        Returns: a View

        """
        return self.search_by_hashes([file_hash])

    @abstractmethod
    def search_by_hashes(self, file_hashes: [], limit: int = None) -> View:
        """
        Searches repository for matches in a list of file hashes
        Args:
            file_hashes: list of sha256 file hashes
            limit: stop searching after limit matches, otherwise, (default) search for every hash in the file_hashes list

        Returns: a View
        """
        pass

    def _extract_search_criteria(self, search):
        file_type = None
        first_seen = None
        tag = None
        size = None

        file_type_arg = re.findall('type:(\S*)', search)
        if file_type_arg:
            file_type = file_type_arg[0]

        first_seen_arg = re.findall('fs:((\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01]))\+', search)
        if first_seen_arg:
            first_seen = first_seen_arg[0][0]

        tag_arg = re.findall('tag:(\S*)', search)
        if tag_arg:
            tag = tag_arg[0]

        size_arg = re.findall('size:([0-9]*)(m|M|mb|MB|k|K|kb|KB|b|B)(\+|\-)', search)
        size_operator = '='
        if size_arg:
            if size_arg[0][1] in ('m', 'M', 'mb', 'MB'):  # size in MB
                size = int(size_arg[0][0]) * 1000000
                if len(size_arg[0]) == 3:
                    size_operator = size_arg[0][2]
            elif size_arg[0][1] in ('k', 'K', 'kb', 'KB'):# size in KB
                size = int(size_arg[0][0]) * 1000
                if len(size_arg[0]) == 3:
                    size_operator = size_arg[0][2]
            else:
                size = int(size_arg[0][0])  # size in bytes
                if len(size_arg[0]) == 2:
                    size_operator = size_arg[0][1]

        '''
        p_arg = re.findall('(p|positives):', search)
        if p_arg:
            positives = p_arg[0]
            logging.WARNING(f"'p' and 'positives' operators not supported yet for {self.__class__}")

        and_arg = re.findall('and', search)
        if and_arg:
            logging.WARNING(f"'and' operators not supported yet for {self.__class__}")

        or_arg = re.findall('or', search)
        if and_arg:
            logging.WARNING(f"'or' operators not supported yet for {self.__class__}")
        '''

        return first_seen, file_type, tag, size, size_operator



