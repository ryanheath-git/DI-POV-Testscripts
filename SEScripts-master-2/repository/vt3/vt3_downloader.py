import aiohttp

from common.version import __version__
from repository.vt.vt_const import VT3_API_BASE_URL
from repository.downloader import Downloader
from repository import file_info_dict_template
import asyncio
from aiohttp import ClientSession
import logging


class VT3Downloader(Downloader):
    def __init__(self, download_handler, api_key):
        """
        Virus Total specific file download concrete class
        Args:
            download_handler:
            api_key: VirusTotal api_key
        """
        super().__init__(download_handler)
        self._api_key = api_key

    def get_session(self):
        _USER_AGENT_FMT = '{agent}; sescripts {version}; gzip'
        if not self._session:
            headers = {
                'X-Apikey': self._api_key,
                'Accept-Encoding': 'gzip',
                'User-Agent': _USER_AGENT_FMT.format_map({
                    'agent': 'unknown', 'version': __version__})
            }

            # if self._user_headers:
            #    headers.update(self._user_headers)

            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),  # , limit=50),
                headers=headers,
                trust_env=False,
                timeout=aiohttp.ClientTimeout(total=300))
        return self._session

    async def download_file(self, session: ClientSession, file_info):
        file_hash = file_info[file_info_dict_template.SHA256_HASH_KEY]
        download_url = f'{VT3_API_BASE_URL}/files/{file_hash}/download'

        try:
            response = await session.get(url=download_url)
        except ( # these are the cases in which there's something (maybe temporarily) borked with this connection
        # attempting a download... however, this issue may not effect the rest of the downloads, so, don't fail other
        # downloads.
            UnicodeDecodeError,
            asyncio.TimeoutError,
            aiohttp.ClientOSError,
            aiohttp.ClientResponseError,
            aiohttp.ServerDisconnectedError,
        ) as e:
            logging.warning(f'{download_url} has failed. Error {str(e)}')
            return None

        if response.status != 200:
            if 400 <= response.status <= 499:
                # if we get here, we're pretty hosed - for any connection or download attempt.
                # This bit is commented out, because it just results in the same error code reported dozens of times
                '''
                if response.content_type == 'application/json':
                    json_response = await response.json()
                    error = json_response.get('error')
                    if error:
                        error_code = error['code']
                        error_msg = error['message']
                        logging.warning(f'Download of {file_info[file_info_dict_template.SHA256_HASH_KEY]} failed. '
                                        f'Error status: {response.status}, Error code: {error_code}, message: {error_msg}')
                '''
            response.raise_for_status()

        await self.download_handler.write_download_http_stream(response.content, file_info)

        return file_info
