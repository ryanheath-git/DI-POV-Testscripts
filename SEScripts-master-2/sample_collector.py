#!/usr/bin/python3
"""
Use to build collections of sample datasets.

Requirements:  see requirements.txt

Disclaimer:
This code is provided as an example of how to build code to demo and test
the Deep Instinct client and Deep Instinct "agentless" products. It is
provided AS-IS/NO WARRANTY. It has limited error checking and logging,
and likely contains defects or other deficiencies. Test thoroughly first,
and use at your own risk. This script and all others in this package
are not a Deep Instinct commercial product and is not officially
supported, although underlying Deep Instinct REST APIs are.

"""

import logging
import pathlib
import time
import argparse
from datetime import date, timedelta
import os

import repository.downloader
from common import interactive as cli
from conf.json_config_parser import JSONConfigParser

# sys.path.append('../')
import test_detection as td
import malware_downloader as md
from repository.downloader import FileDownloadHandler
from common import interactive
from repository.exceptions import FileDoesNotExistInRepository
from repository.vt3.vt3_downloader import VT3Downloader
from repository.vt import vt_const
from repository.malwarebazaar.mb_search import MalwareBazaarSearch


# TODO - a hack for now to check all returned hashes that have been tested against existence in another repository
def secondary_check(hashes):
    #TODO need to be more defensive here... either a check for any results, or .hashes() raises exception
    new_list = MalwareBazaarSearch().search_by_hashes(hashes).hashes()
    return new_list


def sample_collector(dataset_name, api_key, search, numfiles, test_detections_folder, downloads_folder,
                     test_callback=None, download_callback=None, double_check=False):
    test_folder = f"MALWARE_{time.strftime('%Y-%m-%d_T%H%M%S')}"
    fdh = FileDownloadHandler(test_detections_folder, test_folder, test_callback)
    positive_detections, negative_detections = td.test_detection(api_key, search, numfiles, fdh)
    # Note, we won't actually download and test numfiles * 10 samples but rather,
    # we want to make sure that we test enough files to get to numfile samples.  Keep in mind that just
    # because we found a file from VT to test, doesn't mean we will necessarily prevent it.
    # Once we have confirmed positive detections on numfile samples (in the DownloadCallback below), we can
    # kill the remaining
    hashes = positive_detections
    fdh.download_folder.rmdir()

    if not positive_detections:
        # TODO get the messages out of this function and into the main()
        return False
    else:
        interactive.msg(f'Found {len(positive_detections)} positive detections', indent_level=1)

    if double_check:
        interactive.msg(f'Checking Malware Bizarre for existence of samples...', indent_level=1)
        hashes = secondary_check(positive_detections)
        if len(hashes) == 0:
            return False

    fdh = FileDownloadHandler(downloads_folder, dataset_name, download_callback)
    hashes = VT3Downloader(fdh, api_key).download_files_from_hashes(hashes)

    # write the manifest file at the same level as the download folder - easier to manage if we can only send hashes
    manifest_file = pathlib.Path(fdh.root_download_folder, f"{dataset_name}_manifest.txt")
    with open(manifest_file, 'a') as f:
        for entry in hashes:
            f.write(f'{entry}\n')

    return True


class DownloadCallback(repository.downloader.DownloadCallback):
    def __init__(self, maxfiles, start_message):
        super().__init__()
        self.maxfiles = maxfiles
        self.file_counter = 0
        self.start_message = start_message
        md.kill_switch = False

    def download_start(self):
        print(self.start_message)

    def download_finish(self):
        print(self.start_message + ' Done.\n')

    def download_file_start(self, fullpath_filename: pathlib.Path):
        pass

    def download_file_end(self, filename):
        self.file_counter += 1
        percentage_complete = int((self.file_counter / self.maxfiles) * 100)
        print(f'{percentage_complete}%\r', end='')


def main():
    cfg = JSONConfigParser()
    default_api_key = ''
    default_test_folder = ''
    default_collection_folder = ''
    # Read local config json file.
    if pathlib.Path('conf/config.json').exists():
        cfg.read_file(pathlib.Path('conf/config.json'))
        # Get default values from our config file
        default_api_key = cfg.get('virustotal', 'api_key')
        default_test_folder = cfg.get('downloader', 'test_folder')
        default_collection_folder = cfg.get('downloader', 'collection_folder')

    os.system('')  # for reasons that baffle the mind, this is necessary to enable colored text in Windows

    class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKCYAN = '\033[96m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

        def disable(self):
            self.HEADER = ''
            self.OKBLUE = ''
            self.OKGREEN = ''
            self.OKCYAN = ''
            self.WARNING = ''
            self.FAIL = ''
            self.ENDC = ''
            self.UNDERLINE = ''
            self.BOLD = ''

    """Download the top-n results of a given Intelligence search."""
    parser = argparse.ArgumentParser(description="""Helper for building a POV sample collections.  User can submit one or more 
    Virus TotalTest searches, which this script will 1) test which files are detected by DI, and then 2) download 
    those files
                                     """,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     epilog="")
    required_named = parser.add_argument_group('required named arguments')
    required_named.add_argument("-a", "--apikey", dest="api_key", default=default_api_key,
                                help="Virus Total API KEY")
    parser.add_argument("-t", "--testpath", dest="testpath", default=default_test_folder,
                        help='path for testing downloaded files - Deep Instinct should be able to scan this folder path')
    parser.add_argument("-o", "--outpath", dest="outpath", default=default_collection_folder,
                        help='where resulting tested files will downloaded to- Deep Instinct needs to ignore '
                             'this path')
    parser.add_argument("-c", "--check", default='none', choices=['none', 'MB'],
                        help='Check for existence of malware samples in another file repository')

    args = parser.parse_args()

    print(
        f'''{bcolors.OKBLUE}                                                                                ,,                             
`7MM"""Yb.                                   `7MMF'                      mm     db                       mm    
  MM    `Yb.                                   MM                        MM                              MM    
  MM     `Mb  .gP"Ya   .gP"Ya `7MMpdMAo.       MM  `7MMpMMMb.  ,pP"Ybd mmMMmm `7MM  `7MMpMMMb.  ,p6"bo mmMMmm  
  MM      MM ,M'   Yb ,M'   Yb  MM   `Wb       MM    MM    MM  8I   `"   MM     MM    MM    MM 6M'  OO   MM    
  MM     ,MP 8M"""""" 8M""""""  MM    M8       MM    MM    MM  `YMMMa.   MM     MM    MM    MM 8M        MM    
  MM    ,dP' YM.    , YM.    ,  MM   ,AP       MM    MM    MM  L.   I8   MM     MM    MM    MM YM.    ,  MM    
.JMMmmmdP'    `Mbmmd'  `Mbmmd'  MMbmmd'      .JMML..JMML  JMML.M9mmmP'   `Mbmo.JMML..JMML  JMML.YMbmd'   `Mbmo 
                                MM                                                                             
                              .JMML.                                                                           
    {bcolors.ENDC}                            
    ''')

    if not args.api_key:
        print(
            f'{bcolors.FAIL}Virus Total API Key not set in conf/config.py or not supplied as an argument.  Please see help (-h or --help){bcolors.ENDC}')
        exit(1)

    test_path = pathlib.Path(args.testpath)
    if not test_path.is_dir():
        try:
            test_path.mkdir(parents=True, exist_ok=True)
        except:
            print(f'{bcolors.FAIL}{test_path} either is not a valid path or cannot be accessed{bcolors.ENDC}')
            exit(1)

    collection_path = pathlib.Path(args.outpath)
    if not collection_path.is_dir():
        try:
            collection_path.mkdir(parents=True, exist_ok=True)
        except:
            print(f'{bcolors.FAIL}{collection_path} either is not a valid path or cannot be accessed{bcolors.ENDC}')
            exit(1)

    print('')
    print(f'Samples will be tested on: {test_path}')
    print('')
    print(f'Samples will be collected on: {collection_path}')

    print('')
    collection_name_choices = ['sample_collection']
    for path in collection_path.iterdir():
        if path.is_dir() and path.name != 'sample_collection':
            collection_name_choices.append(path.name)
    collection_name = cli.input_selection_or_string(
        'Enter the name for this sample collection or select an existing collection',
        choices=collection_name_choices,
        default=collection_name_choices[0],
        render_flat=True)
    outpath_dataset_name = collection_path / collection_name
    outpath_dataset_name.mkdir(exist_ok=True)

    datasets = {}
    dataset_id = 1
    while True:
        dataset_name_choices = [f'sample_dataset_{dataset_id}']
        for path in outpath_dataset_name.iterdir():
            if path.is_dir() and path.name != f'sample_dataset_{dataset_id}':
                dataset_name_choices.append(path.name)
        name = cli.input_selection_or_string(
            f'Enter a name for this dataset or select an existing dataset to add more files',
            choices=dataset_name_choices,
            default=dataset_name_choices[0],
            render_flat=True)
        datasets[dataset_id] = {}
        datasets[dataset_id]['name'] = name
        print('')
        print(f'\t=======================================================')
        print(f'\t{bcolors.BOLD}Dataset: {name}{bcolors.ENDC}')
        print(f'\t=======================================================')
        interactive = cli.input_yes_no(f'\tInteractive mode?', 'yes')
        if interactive:
            print('\tEntering interactive mode')

            print("\t\tSearch inputs:")
            # TODO if the number of days doesn't trigger the number of samples requested, then ????  perhaps the answer is that when we make samples we are always looking for the latests.  If there's only two samples, then there's only two
            # TODO perhaps start at a day and work back...
            days_ago = cli.input_int('First seen (in days ago)', 0, min_=0, max_=1460, indent_level=3)
            first_seen = date.today() - timedelta(days_ago)
            first_seen_string = first_seen.strftime('%Y-%m-%d')

            type = cli.input_selection_or_string('File type (either select from list or type entry)',
                                                 vt_const.FILETYPE_LIST,
                                                 default='pe',
                                                 indent_level=3,
                                                 render_flat=True)

            positive_verdicts = cli.input_string('Positive verdicts', '35+',
                                                 vt_const.REGEX_POSITIVES,
                                                 indent_level=3)

            size = cli.input_string('Size (0kb to 99mb)',
                                    default='1mb-',
                                    str_format=vt_const.REGEX_SIZE,
                                    indent_level=3)

            vendor_clean = ''
            if cli.input_yes_no('Compare against vendor:clean?', default='no', indent_level=3):
                vendor_clean = cli.input_selection("Vendor clean",
                                                   vt_const.REDUCED_VENDOR_LIST,
                                                   default="microsoft",
                                                   indent_level=3,
                                                   render_flat=True)
                vendor_clean = f'{vendor_clean}:clean'

            additional_attr = cli.input_string(
                'Additional search attributes (note: NOT tag:corrupt automatically added)) ',
                default='',
                indent_level=3)

            maxfiles = cli.input_int(f'Maximum files to test', 20, min_=1, max_=5000, indent_level=2)

            search = f'fs:{first_seen_string}+ type:{type} p:{positive_verdicts} size:{size} {vendor_clean} {additional_attr} NOT tag:"corrupt" '
        else:
            search = cli.input_string('Enter Virus Total search', indent_level=2)
            maxfiles = cli.input_int(f'Maximum files to test', 20, min_=1, max_=5000, indent_level=2)

        datasets[dataset_id]['search'] = search
        datasets[dataset_id]['maxfiles'] = maxfiles

        print('')
        print(f'\tDataset {datasets[dataset_id]["name"]} will be tested and built on the search criteria:')
        print(f'\t\t{datasets[dataset_id]["search"]}')
        print(f'\twith a maximum of {datasets[dataset_id]["maxfiles"]} files')

        print(f'\t=======================================================')
        print('')
        onward = cli.input_yes_no('Define another dataset (y/n)', 'n')
        print('')
        if not onward:
            break
        dataset_id += 1

    print('')
    print(f'The sample collection {collection_name} will be built with the following datasets:')
    for dataset in datasets.values():
        print(f'\tDataset: {dataset["name"]}')
        print(f'\tVT criteria: {dataset["search"]}')
        print(f'\tMaxfiles: {dataset["maxfiles"]}')
        print('')
    print('')
    input(f'Press any key to begin testing and building of collection: {collection_name}')

    print('')
    print(f'Begin {collection_name} test and build')

    for dataset in datasets.values():
        print(f'-----------------------------------------------')
        name = dataset["name"]
        print(f'Build dataset: {name}')
        search = dataset['search']
        print(f'     Search: {search}')
        maxfiles = dataset['maxfiles']
        print(f'     Maxfiles: {maxfiles}')
        logging.getLogger().setLevel(logging.ERROR)
        test_callback = DownloadCallback(maxfiles, "Testing samples...")
        download_callback = DownloadCallback(maxfiles, "Downloading samples...")

        sample_check = False
        if args.check == 'MB':
            sample_check = True

        success = sample_collector(name, args.api_key, search, maxfiles, test_path,
                                   outpath_dataset_name, test_callback, download_callback, sample_check)
        if not success:
            interactive.warning_prompt(f'No samples detected for {search}.  Perhaps expand days searched or loosen '
                                       f'the search criteria', indent_level=1)

        logging.getLogger().setLevel(logging.INFO)
        print()
        print(f'Done with dataset: {name}')

    print('')
    print('***************************************************************')
    print(f'* Datasets for {collection_name} have been downloaded to: ')
    print(f'* {outpath_dataset_name}')
    print('***************************************************************')


if __name__ == '__main__':
    main()
