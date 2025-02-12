import asyncio
import logging
import pathlib
import threading
import re
from pathlib import Path
import sys

from abc import ABC, abstractmethod

import aiohttp
import pyzipper
from pyzipper import AESZipFile
from requests.models import Response
import aiofiles
from aiohttp.streams import StreamReader
from aiohttp import ClientSession
from repository.view import View
from repository import file_info_dict_template


class Downloader(ABC):
    def __init__(self, download_handler):
        self.download_handler = download_handler
        self._session = None

    def get_session(self):
        '''
        Override in concrete class if ClientSession needs more information to establish a client session connection
        Returns:

        '''
        if not self._session:
            self._session = ClientSession(trust_env=True)

        return self._session

    @abstractmethod
    async def download_file(self, session: ClientSession, file_info):
        """
        Downloads the file with the given match to the file_info from a repository.

        Implemented in concrete classes file downloading specific to the repository being queried and any pre- and
        post-processing that needs to occur.

        File will be downloaded to location specified by the DownloadHandler passed in the initialization of this class

        Args:
            session: aiohttp ClientSession
            file_info: a file_info

        Returns: the file_hash if the download succeeded

        """
        pass

    def download_files_from_hashes(self, hash_list):
        """
        Supply a list of file hashes and download associated files.
        Args:
            hash_list: a list of sha256 hashes to download
        Returns: a list of successfully downloaded files by hash

        Files will be downloaded to location specified by the DownloadHandler passed in the initialization of this class

        """
        res = self._download_files_in_hashlist(hash_list)

        # this is needed to handle some weird Windows python event loop issue
        if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        hashes_downloaded = asyncio.run(res)
        return hashes_downloaded

    def download_files_in_view(self, view: View):
        """
        Using a repository.View (a result from a repository.Search), download all files.
        Args:
            view: a repository.View

        Returns: a list of file info dicts

        """
        res = self._download_files_in_view(view)
        # this is needed to handle some weird Windows python event loop issue
        if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        manifest = asyncio.run(res)

        return manifest


    async def _download_files_in_hashlist(self, hash_list):
#        async with ClientSession(trust_env=True) as self._session:
        async with self.get_session():
            tasks = []
            for file_hash in hash_list:
                file_info = file_info_dict_template.new_file_info_dict(file_hash)
                tasks.append(asyncio.ensure_future(
                    self.download_file(self.get_session(), file_info)
                ))

            files_downloaded = await asyncio.gather(*tasks)

        return files_downloaded

    async def _download_files_in_view(self, view):

        file_infos = view.to_file_info_dict()
        #async with ClientSession(trust_env=True) as self._session:
        async with self.get_session():
            tasks = []
            for file_info in file_infos:
                tasks.append(asyncio.ensure_future(
                    self.download_file(self.get_session(), file_info)
                ))

            files_downloaded = await asyncio.gather(*tasks)

            manifest = []
            for file_info in files_downloaded:
                manifest.append(file_info)

        return manifest


class DownloadCallback(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def download_start(self):
        pass

    @abstractmethod
    def download_finish(self):
        pass

    @abstractmethod
    def download_file_start(self, fullpath_filename: pathlib.Path):
        pass

    @abstractmethod
    def download_file_end(self, fullpath_filename: pathlib.Path):
        pass


class DownloadHandler(ABC):
    """
    This is the base class for handling downloads of files from a malware repository.  It controls the where files
    will be downloaded to - i.e., as a file on disk, or an encrypted zipfile, and retqins information on file download
    location.  It also notifies listeners of the status of a download using a callback class.
    """

    def __init__(self, root_download_folder, download_name, download_callback=None, filename_format='{file_hash}'):
        self.root_download_folder = root_download_folder
        self.download_name = download_name
        # note that self.download_folder is not set here... it's set up differently whether a File... or Zip...
        self.download_callback = download_callback
        self.filename_format = filename_format  #TODO check if this is valid

    def create_download_folder(self, folder: Path):
        if not folder.exists():
            folder.mkdir(parents=True, exist_ok=True)
        return folder

    def set_download_callback(self, download_callback):
        self.download_callback = download_callback

    # implementation of DownloadCallback
    def download_start(self):
        if isinstance(self.download_callback, DownloadCallback):
            self.download_callback.download_start()

    def download_finish(self):
        if isinstance(self.download_callback, DownloadCallback):
            self.download_callback.download_finish()

    def download_file_start(self, file):
        if isinstance(self.download_callback, DownloadCallback):
            self.download_callback.download_file_start(file)

    def download_file_end(self, file):
        if isinstance(self.download_callback, DownloadCallback):
            self.download_callback.download_file_end(file)

    @abstractmethod
    def write_download_stream(self, http_response: Response, file_info):
        """
        Deprecated
        Args:
            http_response: requests.models.Response object - a response from an HTTP request
            file_info: a file_info dict

        Returns: nothing

        """
        pass

    @abstractmethod
    async def write_download_http_stream(self, aiohttp_response_content: StreamReader, file_info):
        """
        Given an aiohttp response, write content of requested download to disk
        Args:
            file_info: a file_info dict
            aiohttp_response_content: aiohttp.streams.StreamReader object

        Returns:

        """

    def format_filename(self, file_info):
        '''
        Formats the filename based on the filename_format supplied in the constructor of this class
        Args:
            file_info: a file_info dict

        Returns:

        '''
        file_name = self.filename_format
        if re.search('{file_hash}', file_name):
            file_name = re.sub('{file_hash}', file_info[file_info_dict_template.SHA256_HASH_KEY], file_name)
        if re.search('{file_name}', file_name):
            file_name = re.sub('{file_name}', file_info[file_info_dict_template.FILE_NAME_KEY], file_name)
        if re.search('{file_ext}', file_name):
            file_name = re.sub('{file_ext}', file_info[file_info_dict_template.FILE_EXT_KEY], file_name)
        if re.search('{first_seen}', file_name):
            datetime = file_info[file_info_dict_template.FIRST_SEEN_KEY]
            dt = datetime.strftime("%m_%d_%Y %H_%M_%S")
            file_name = re.sub('{first_seen}', dt, file_name)
        if re.search('{file_class}', file_name):
            if file_info[file_info_dict_template.POPULAR_THREAT_CLASSIFICATION]:
                file_name = re.sub('{file_class}', file_info[file_info_dict_template.POPULAR_THREAT_CLASSIFICATION],
                                   file_name)
            else:
                file_name = re.sub('{file_class}', '(no classification)',
                                   file_name)

        file_name = re.sub('/', '_', file_name)
        file_name = re.sub(':', '_', file_name)

        return file_name


class FileDownloadHandler(DownloadHandler):
    def __init__(self, root_download_folder, download_name, download_callback=None, file_format='{file_hash}'):
        super().__init__(root_download_folder, download_name, download_callback, file_format)
        self.download_folder = pathlib.Path(self.root_download_folder, self.download_name)
        self.create_download_folder(self.download_folder)
        super().download_start()

    def write_file(self, content, file_info):
        """

        Args:
            content:
            file_info:

        Returns:

        """
        file_name = self.format_filename(file_info)
        full_name = pathlib.Path(self.download_folder, file_name)
        super().download_file_start(full_name)
        with full_name.open('wb') as fd:
            fd.write(content)
        super().download_file_end(full_name)

    def write_download_stream(self, http_response: Response, file_info: str):
        file_name = self.format_filename(file_info)
        full_name = pathlib.Path(self.download_folder, file_name)
        super().download_file_start(full_name)
        with open(full_name, 'wb') as fd:
            for chunk in http_response.iter_content(chunk_size=4096):
                fd.write(chunk)
        super().download_file_end(full_name)

    async def write_download_http_stream(self, aiohttp_response_content: StreamReader, file_info):
        file_name = self.format_filename(file_info)
        full_name = pathlib.Path(self.download_folder, file_name)
        super().download_file_start(full_name)
        async with aiofiles.open(full_name, 'wb') as fd:
            async for data in aiohttp_response_content.iter_any():
                await fd.write(data)

        super().download_file_end(full_name)


class EncryptedZipDownloadHandler(DownloadHandler):
    def __init__(self, root_download_folder, download_name, download_callback=None, password=b'infected', file_format='{file_hash}'):
        super().__init__(root_download_folder, download_name, download_callback, file_format)
        self.download_folder = pathlib.Path(root_download_folder)
        self.create_download_folder(self.download_folder)  # will create the download folder if not exist
        self.password = password
        self.zipfile_name = pathlib.Path(self.download_folder, self.download_name)

        self.lock = threading.Lock()

    def write_download_stream(self, http_response, file_info):
        self.lock.acquire()
        file_name = self.format_filename(file_info)
        super().download_file_start(file_name)

        malware = b''
        for chunk in http_response.iter_content(chunk_size=4096):
            malware += chunk

        with AESZipFile(self.zipfile_name, 'a', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as pz:
            pz.setpassword(self.password)
            pz.writestr(file_name, malware)

        super().download_file_end(file_name)
        self.lock.release()

    async def write_download_http_stream(self, aiohttp_response_content: StreamReader, file_info):
        file_name = self.format_filename(file_info)
        super().download_file_start(file_name)

        malware = b''
        async for chunk in aiohttp_response_content.iter_any():
            malware += chunk

        with AESZipFile(self.zipfile_name, 'a', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as pz:
            pz.setpassword(self.password)
            pz.writestr(file_name, malware)

        super().download_file_end(file_name)
