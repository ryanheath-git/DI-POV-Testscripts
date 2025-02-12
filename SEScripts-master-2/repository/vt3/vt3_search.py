#
# Copyright 2012 Google Inc. All Rights Reserved.
# Revised by DI

"""
This class serves as a helper class to paginate over a given VT Intelligence search and return matching hashes
"""
import asyncio
import pathlib
import datetime
import re
import sys

import urllib.parse

from repository.search import Search
from repository.view import View
from repository.vt import vt_const
from repository import file_info_dict_template

from aiohttp import ClientSession


class Error(Exception):
    """Base-class for exceptions in this module."""


class InvalidQueryError(Error):
    """Search query is not valid."""


class VT3Search(Search):
    def __init__(self, api_key):
        """

        Args:
            api_key: this will default to the value in conf/config.VirusTotal.api_key
        """
        super().__init__()
        self._api_key = api_key

    def search_by_hashes(self, file_hashes, limit: int = None):
        """
        Find all hashes that exist in the VT repository, collect all file information and return a View
        Args:
            file_hashes: list of sha256 file hashes
            limit:

        Returns: a View

        """
        res = self._search_by_hashes_async(file_hashes, limit)
        # this is needed to handle some weird Windows python event loop issue
        if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        file_info_list = asyncio.run(res)

        view = View(file_info_list)
        return view

    def search_by_query(self, search, limit):
        """
        Args:
            search: A virus total search query
            limit: maximum number of file hashes to return

        Returns: a VTView of retrieved hashes matching search
        """
        cursor = None
        file_infos = []
        iterations = limit // 300  # virus total limits the number of results to 300, so if we are asking for more,
        remainder = limit % 300  # then we'll need to perform 2 or more iterations
        for i in range(0, iterations + 1):
            if i == iterations:
                count = remainder
            elif iterations > 0:
                count = 300
            res = self._search_by_query_async(search, count, cursor)

            if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            json_response, cursor = asyncio.run(res)
            file_infos += json_response['data']

        hashes = []
        for file_info in file_infos:
            hashes.append(file_info['id'])

        view = self.search_by_hashes(hashes, limit)
        return view  # request additional file information and return View

    async def _search_by_hashes_async(self, file_hashes, limit: int = None):
        headers = {'x-apikey': self._api_key}
        async with ClientSession(headers=headers, trust_env=True) as session:
            tasks = []
            for file_hash in file_hashes:
                tasks.append(asyncio.ensure_future(
                    self._get_file_info(session, file_hash)
                ))

            file_infos = await asyncio.gather(*tasks)

        clean_list = [i for i in file_infos if i]  # check for None values and clean them out

        if limit:
            clean_list = clean_list[:limit]

        return clean_list

    async def _get_file_info(self, session: ClientSession, file_hash):

        response = await session.get(f'{vt_const.VT3_API_BASE_URL}/files/{file_hash}', ssl=False)

        if response.status == 404:
            return None  # the file just doesn't exist

        response.raise_for_status()

        response_json = await response.json()
        info = response_json['data']

        file_stem = self._parse_filename(info['attributes'])
        file_ext = info['attributes']['type_extension']

        epoch = info['attributes']['first_submission_date']
        ts = datetime.datetime.fromtimestamp(epoch)

        file_class = ''
        if 'popular_threat_classification' in info['attributes']:
            file_class = info['attributes']['popular_threat_classification']['suggested_threat_label']

        file_info = file_info_dict_template.new_file_info_dict(sha256_hash=file_hash,
                                                               file_name=file_stem,
                                                               file_type=info['attributes']['type_tag'],
                                                               first_seen=ts.strftime('%Y-%m-%d %H:%M:%S'),
                                                               file_size=info['attributes']['size'],
                                                               file_ext=file_ext,
                                                               popular_threat_classification=
                                                               file_class)
        return file_info

    # there's nothing particulary beneficial running this async, since it can only be called once to retrieve up to
    # 300 results, and for limits > 300, one search has to complete before the next on can be made.  However, since
    # this module is using aiohttp, we have to encapsulate these calls into something that handle async/await(s)
    async def _search_by_query_async(self, search, limit, cursor):
        headers = {'x-apikey': self._api_key}
        async with ClientSession(headers=headers, trust_env=True) as session:
            search = urllib.parse.quote(search)

            # It may seem like wasted time to only ask for descriptors and not all the file information in this query.
            # However, for large queries there is a significant time difference, when asking for all file information
            # during a search, or just the descriptors. For example, searches for 300 files can take 9+ seconds when
            # retrieving all info, whereas asking for just the descriptors (basically the file
            # hashes) takes a second.  Once this query is complete, asynchronous requests can be made for each
            # individual file's information.  While at first this may seem counter-intuitive, 300 (from our example)
            # concurrent asynchronous requests is still more than twice as fast asking for a bulk request of
            # 300 file infos in one request.
            #
            # Furthermore, retrieving file information one by one, opens up the possibility of starting a download on
            # a file as each request for file information completes.
            search_url = f'{vt_const.VT3_API_BASE_URL}/intelligence/search?query={search}&limit={limit}&descriptors_only=true'
            if cursor:
                search_url += f'&cursor={cursor}'
            response = await session.get(url=search_url, ssl=False)
            response.raise_for_status()

            json = await response.json()
            continuation_cursor = json['meta']['cursor'] if 'cursor' in json['meta'].keys() else None

        return json, continuation_cursor

    def _parse_filename(self, json_response):
        """
        Parses the most 'useful' file name from the VT attributes

        Args:
            json_response: json data from VT API call for file info

        Returns: The 'best' file name, or the hash is not available. VT's interpretation of the best name for this file.

        """
        meaningful_file_name = json_response.get('meaningful_name', None)
        if meaningful_file_name:
            path = pathlib.Path(meaningful_file_name)
            stem = path.stem
            stem = re.split('\\\\', stem).pop()  # in the event that the filename stem still has \\ in them
            return stem

        else:
            return '(not available)'
