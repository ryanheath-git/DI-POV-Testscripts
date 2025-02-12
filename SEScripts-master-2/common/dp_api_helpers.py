import requests
import base64

def scan_file_data(data, scan_url, encoded=False):
    if encoded:
        #encode data and set URL to match
        data = base64.b64encode(data)
        request_url = f'{scan_url}/scan/base64'
    else:
        #leave data as-is and set URL to match
        request_url = f'{scan_url}/scan/binary'

    # send scan request, capture response
    try:
        response = requests.post(request_url, data=data, timeout=20, verify=False)
    except requests.exceptions.RequestException as e:
        raise e

    # validate response code, return verdict as Python dictionary
    if response.status_code == 200:
        return response
    else:
        print('ERROR: Unexpected return code', response.status_code, 'on POST to', request_url)
        return response


def scan_file(file_name, scan_url, encoded=False):
    # read file from disk. rb means opens the file in binary format for reading
    with open(file_name, 'rb') as f:
        #read file
        data = f.read()
        #close file
        f.close()
    return scan_file_data(data, scan_url, encoded)