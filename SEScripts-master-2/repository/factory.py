from repository import const
from repository.exceptions import RepositorySearchCreationError
from repository.search import Search
from repository.downloader import Downloader
from repository.malwarebazaar.mb_search import MalwareBazaarSearch
from repository.vt.vt_search import VTSearch
from repository.malwarebazaar.mb_downloader import MalwareBazaarDownloader
from repository.vt.vt_downloader import VTDownloader
from repository.vt3.vt3_search import VT3Search
from repository.vt3.vt3_downloader import VT3Downloader

def create_downloader_by_id(repository_id, *args) -> Downloader:
    """
    Creates a Search based on the repository_id
    Args:
        repository_id:
        search:
        numfile:

    Returns: a Downloader

    """
    if repository_id == const.MALWAREBAZAAR_IDENTIFIER:
        if len(args) < 1:
            raise RepositorySearchCreationError(missing_args='No download handler supplied')
        download_handler = args[0]
        return MalwareBazaarDownloader(download_handler)
    elif repository_id == const.VIRUSTOTAL_IDENTIFIER:
        if len(args) < 2:
            raise RepositorySearchCreationError(missing_args='No download handler or VT API key supplied')
        download_handler = args[0]
        api_key = args[1]
        return VTDownloader(download_handler, api_key)
    elif repository_id == const.VIRUSTOTAL3_IDENTIFIER:
        if len(args) < 2:
            raise RepositorySearchCreationError(missing_args='No download handler or VT API key supplied')
        download_handler = args[0]
        api_key = args[1]
        return VT3Downloader(download_handler, api_key)

def create_search_by_id(repository_id, *args) -> Search:
    """
    Creates a Search based on the repository_id
    Args:
        repository_id: identifier of repository as defined in const file
        args: additional arguments

    Returns: a Search

    """

    if repository_id == const.MALWAREBAZAAR_IDENTIFIER:
        mb_repository_search = MalwareBazaarSearch()
        return mb_repository_search
    elif repository_id == const.VIRUSTOTAL_IDENTIFIER:
        if len(args) < 1:
            raise RepositorySearchCreationError(missing_args='No VT API key supplied')
        api_key = args[0]
        vt_repository_search = VTSearch(api_key)
        # TODO perhaps test that this is a valid key.... free or enterprise
        return vt_repository_search
    elif repository_id == const.VIRUSTOTAL3_IDENTIFIER:
        if len(args) < 1:
            raise RepositorySearchCreationError(missing_args='No VT API key supplied')
        api_key = args[0]
        vt_repository_search = VT3Search(api_key)
        # TODO perhaps test that this is a valid key.... free or enterprise
        return vt_repository_search
