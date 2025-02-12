"""
See readme.md for information on this script.

Required modules: See requirements.txt

Disclaimer:
This code is provided as an example of how to build code to demo and test
the Deep Instinct client and Deep Instinct "agentless" products. It is
provided AS-IS/NO WARRANTY. It has limited error checking and logging,
and likely contains defects or other deficiencies. Test thoroughly first,
and use at your own risk. This script and all others in this package
are not a Deep Instinct commercial product and is not officially
supported, although underlying Deep Instinct REST APIs are.

"""
import argparse
import os
from repository.downloader import FileDownloadHandler
import pathlib
import time
from repository.vt3.vt3_search import VT3Search
from repository.vt3.vt3_downloader import VT3Downloader
from common import interactive
from conf.json_config_parser import JSONConfigParser
from repository import file_info_dict_template

LOCAL_STORE = 'MALWARE'

RESULTS_DOWNLOAD_FOLDER_KEY = 'download_folder'
RESULTS_DETECTED_KEY = 'detected'
RESULTS_UNDETECTED_KEY = 'undetected'


def test_detection(api_key, search, numfiles, fdh: FileDownloadHandler):
    view = VT3Search(api_key).search_by_query(search, numfiles)
    if view.empty():
        return [], []

    #downloaded_files = VT3Downloader(fdh, api_key).download_files_in_view(view)
    hashes_downloaded = VT3Downloader(fdh, api_key).download_files_from_hashes(view.hashes())

    # put a wait in here allow DI to do the final file scans, and checkins with d-cloud which may possibly reverse a verdict.
    # not sure what exactly just how long we need to wait....
    negative_list = os.listdir(fdh.download_folder)
    for file in negative_list:
        if '.' in file:
            negative_list.remove(file)

    positive_list = []
    for file_info in hashes_downloaded:
        file_hash = file_info[file_info_dict_template.SHA256_HASH_KEY]
        if file_hash not in negative_list:
            positive_list.append(file_hash)

    # now that we've finished, get rid of downloads we didn't detect on
    for file in negative_list:
        filepath = pathlib.Path(fdh.download_folder, file)
        if filepath.is_file():
            filepath.unlink()

    return positive_list, negative_list


def main():
    cfg = JSONConfigParser()
    default_api_key = ''
    default_test_folder = ''
    # Read local config json file.
    if pathlib.Path('conf/config.json').exists():
        cfg.read_file(pathlib.Path('conf/config.json'))
        # Get values from our test_config.json file
        default_api_key = cfg.get('virustotal', 'api_key')
        default_test_folder = cfg.get('downloader', 'test_folder')

    """Download the top-n results of a given Intelligence search."""
    parser = argparse.ArgumentParser(description="""Download files based on a  
                                      VirusTotal Intelligence search and test which files Deep instinct detects on.""",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     epilog="NOTE: Deep Instinct should be installed on device where this script is "
                                            "run, and set to some level of prevent mode.")
    parser.add_argument("search", help="a Virus Total Intelligence search", nargs='+')
    required_named = parser.add_argument_group('required named arguments')
    required_named.add_argument("-a", "--apikey", dest="apikey", default=default_api_key, help="Virus Total API KEY")
    parser.add_argument("-n", "--numfiles", type=int, dest="numfiles", default=100,
                        help='limits the number of files to test')
    parser.add_argument("-t", "--testpath", dest="testpath", default=default_test_folder,
                        help='parent output path for downloaded files')

    args = parser.parse_args()
    searchargs = args.search
    search = ' '.join(searchargs)
    api_key = args.apikey
    download_parent_folder = args.testpath
    numfiles = args.numfiles

    fdh = FileDownloadHandler(download_parent_folder, f"{LOCAL_STORE}_{time.strftime('%Y-%m-%d_T%H%M%S')}")

    interactive.msg(f'Testing files at: {fdh.download_folder}')

    positive_list, negative_list = test_detection(api_key, search, numfiles, fdh)
    if len(positive_list) == 0 and len(negative_list) == 0:
        interactive.warning_prompt(f'No files found for the search {search} file count {numfiles}.  Potentially expand '
                                   f'search days or form a less restrictive search.')
    else:
        interactive.msg(f"Files detected: {positive_list}", indent_level=1)
        interactive.msg(f"Files undetected: {negative_list}", indent_level=1)

    with open(pathlib.Path(fdh.download_folder, 'detected.txt'), 'w') as f:
        for h in positive_list:
            f.write(f"{h}\n")

    with open(pathlib.Path(fdh.download_folder, 'undetected.txt'), 'w') as f:
        for h in negative_list:
            f.write(f"{h}\n")


if __name__ == '__main__':
    main()
