"""
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
import json
import logging
import sys
import argparse

import requests
from flask import Flask, session, flash, redirect, url_for, request, send_from_directory, send_file
from werkzeug.utils import secure_filename
from common import dp_api_helpers as dp

UPLOAD_FOLDER = 'webapp/uploads'
ALLOWED_EXTENSIONS = {'*'}
DP_URL = 'http://localhost:5000'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.static_folder = f'{app.root_path}/webapp'
app.static_url_path = ''
# app.jinja_env.line_statement_prefix = '#'
# app.jinja_env.variable_start_string = "{$"
# app.jinja_env.variable_start_string = "$}"
# images = Images(app)
# ui = FlaskUI(app)  # feed the parameters

LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

list_of_uploaded_files = []


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
@app.route('/index.html')
def index():
    return app.send_static_file('index.html')


@app.route('/file_list', methods=['GET'])
def file_list():
    file_list_json = json.dumps({'files': list_of_uploaded_files})
    return file_list_json


@app.route('/delete_file_list', methods=['DELETE'])
def delete_file_list():
    list_of_uploaded_files.clear()


@app.route('/upload', methods=['POST'])
def upload_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:  # and allowed_file(file.filename):
        try:
            response = dp.scan_file_data(file, app.config['DP_URL'])
        except requests.exceptions.RequestException as e:
            logging.error(f'Error connecting to {app.config["DP_URL"]}. {e.args[0]}')

        if response.status_code != 200:
            return {'scan_status': 'FAILED',
                    'scan_verdict': 'NA',
                    'scan_response': 'NA',
                    'error': e}

        json = response.json()
        if (json["verdict"] == "Benign"):
            # not really saving the file to disk, just capturing that the file was uploaded
            # filename = secure_filename(file.filename)
            # filepath = pathlib.Path(app.config['UPLOAD_FOLDER'], filename)
            # file.save(filepath)
            list_of_uploaded_files.append(file.filename)
            return {'scan_status': 'OK',
                    'scan_verdict': 'benign',
                    'scan_response': json}
        elif (json["verdict"] == "Malicious"):
            return {'scan_status': 'OK',
                    'scan_verdict': 'malicious',
                    'scan_response': json}
        else:
            return {'scan_status': 'OK',
                    'scan_verdict': 'could_not_scan',
                    'scan_response': json}


def main():
    parser = argparse.ArgumentParser(description="""Send to agentless connector""",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     epilog="")
    parser.add_argument("-c", "--connector", dest="connector", default="127.0.0.1",
                        help='ipaddress of agentless connector')
    parser.add_argument("-p", "--port", dest="port", default=5000,
                        help='agentless connector port')
    parser.add_argument("-i", "--insecure", action='store_true',
                        help='use http instead of https')

    args = parser.parse_args()
    if args.insecure:
        protocol = 'http'
    else:
        protocol = 'https'

    DP_URL = f"{protocol}://{args.connector}:{args.port}"
    app.config['DP_URL'] = DP_URL
    print(f"Connecting to agentless connect at: {DP_URL}")

    app.run(host='0.0.0.0', debug=True, port=5555)


if __name__ == "__main__":
    main()
