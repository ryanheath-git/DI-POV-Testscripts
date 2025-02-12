
from repository.vt.vt_const import INTELLIGENCE_DOWNLOAD_URL
from repository.downloader import Downloader
from repository import file_info_dict_template
import asyncio
from aiohttp import ClientSession


class VTDownloader(Downloader):
    def __init__(self, download_handler, api_key):
        """
        Virus Total specific file download concrete class
        Args:
            download_handler:
            api_key: VirusTotal api_key
        """
        super().__init__(download_handler)
        self._api_key = api_key

    async def download_file(self, session: ClientSession, file_info):
        file_hash = file_info[file_info_dict_template.SHA256_HASH_KEY]
        download_url = f'{INTELLIGENCE_DOWNLOAD_URL}?hash={file_hash}&apikey={self._api_key}'

        response = await session.get(url=download_url, ssl=False)

        if response.status != 200:
            return None
        #response.raise_for_status()

        await self.download_handler.write_download_http_stream(response.content, file_info)

        return file_info



