#
# Copyright 2012 Google Inc. All Rights Reserved.
# Revised by DI

"""
This class serves as a helper class to paginate over a given VT Intelligence search and return matching hashes
"""

import logging
import pathlib
import time
import datetime
import re

import requests
from repository.search import Search
from repository.view import View
from repository.vt import vt_const
from repository import file_info_dict_template


class Error(Exception):
    """Base-class for exceptions in this module."""


class InvalidQueryError(Error):
    """Search query is not valid."""


class VTSearch(Search):
    def __init__(self, api_key):
        """

        Args:
            api_key: this will default to the value in conf/config.VirusTotal.api_key
        """
        super().__init__()
        self._api_key = api_key

    def search_by_query(self, search, limit):
        """
        This VT search by query is essentially the exact same query that a user performs when on the VT website.  Pages
        are pulled 25 file hashes at a time, until
        Args:
            search: A virus total search query
            limit: maximum number of file hashes to return

        Returns: a VTView of retrieved hashes matching search
        """

        hashes = []
        next_page = None
        need_more = True
        try:
            while need_more:
                next_page, tmp_hashes = self._get_matching_files(search, page=next_page)
                if not tmp_hashes:
                    break
                hashes.extend(tmp_hashes)
                if len(hashes) >= limit:
                    hashes = hashes[:limit]
                    need_more = False
                elif not next_page:
                    logging.warning(
                        f'The search condition {search} only returned {len(hashes)} results, '
                        f'so only that many will be downloaded.')
                    need_more = False

        except InvalidQueryError as e:
            logging.error(f"The search query provided is invalid... {e}")
            return []

        view = self.search_by_hashes(hashes, limit)
        return view  # request additional file information and return View

    def search_by_hashes(self, file_hashes, limit: int = None):
        """
        Find all hashes that exist in the VT repository, collect all file information and return a View
        Args:
            file_hashes: list of sha256 file hashes
            limit:

        Returns: a View

        """
        file_info_list = []
        count = 0
        for file_hash in file_hashes:

            file_info = self.get_file_info(file_hash)
            if not file_info:
                continue

            file_info_list.append(file_info)

            if limit:
                count += 1
                if count == limit:
                    break

        view = View(file_info_list)
        return view

    def get_file_info(self, file_hash):
        headers = {'x-apikey': self._api_key}
        response = requests.get(f'{vt_const.VT3_API_BASE_URL}/files/{file_hash}', headers=headers)

        if response.status_code != 200:
            return None
            # raise Exception("VT API call to /file/report returned status code: " + str(response.status_code))

        info = response.json()['data']

        file_stem = self._parse_filename(info['attributes'])

        epoch = info['attributes']['first_submission_date']
        ts = datetime.datetime.fromtimestamp(epoch)

        file_info = file_info_dict_template.new_file_info_dict(sha256_hash=file_hash,
                                                               file_name=file_stem,
                                                               file_type=info['attributes']['type_tag'],
                                                               first_seen=ts.strftime('%Y-%m-%d %H:%M:%S'),
                                                               file_size=info['attributes']['size'])
        return file_info

    def _parse_filename(self, json_response):
        """
        Parses the most 'useful' file name from the VT attributes

        Args:
            json_response: json data from VT API call for file info

        Returns: The 'best' file name, or the hash is not available. VT's interpretation of the best name for this file. Subjective and needs work and then refactoring

        """
        meaningful_file_name = json_response.get('meaningful_name', None)
        if meaningful_file_name:
            path = pathlib.Path(meaningful_file_name)
            stem = path.stem
            stem = re.split('\\\\', stem).pop()  # in the event that the filename stem still has \\ in them
            return stem

        else:
            return '(not available)'

    def _hashes_to_file_infos(self, hashes):
        file_info_list = []
        for sha256_hash in hashes:
            file_info = file_info_dict_template.new_file_info_dict(sha256_hash=sha256_hash)
            file_info_list.append(file_info)

        return file_info_list

    def _get_matching_files(self, search, page=None):
        """
            Get a page of files matching a given Intelligence search.
            @param search:
            @param page:
            @return: Tuple with a token to retrieve the next page of results and a list of sha256
            hashes of files matching the given search conditions.

            Raises:
            InvalidQueryError: if the Intelligence query performed was not valid.
        """

        response = None
        page = page or 'undefined'
        attempts = 0

        params = {'query': search, 'apikey': self._api_key, 'page': page}
        while attempts < 10:
            try:
                response = requests.get(vt_const.INTELLIGENCE_SEARCH_URL, params=params)
                break
            except Exception:
                attempts += 1
                time.sleep(1)
        if not response:
            return (None, None)

        try:
            response_dict = response.json()
        except ValueError:
            return (None, None)

        if not response_dict['result']:
            raise InvalidQueryError(response_dict['error'])

        next_page = response_dict.get('next_page')
        hashes = response_dict.get('hashes', [])
        return next_page, hashes

