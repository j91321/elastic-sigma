import sys
import base64
import requests
import argparse
import json
import os

parser = argparse.ArgumentParser(description='Load kibana-saved-searches json and bulk insert them into Kibana')
parser.add_argument('--url', type=str)
parser.add_argument('--user', type=str)
parser.add_argument('--password', type=str)
args = parser.parse_args()

url = base64.b64decode(args.url).decode('ascii')+'/api/detection_engine/rules/_import?overwrite=true'
username = base64.b64decode(args.user).decode('ascii')
password = base64.b64decode(args.password).decode('ascii')
headers = {
  'kbn-xsrf': 'kibana'
  }

artifacts_path = './es-rules-output/'
directory = os.fsencode(artifacts_path)

exit_code = 0

for sigma_rule in os.listdir(directory):
    filename = os.fsdecode(sigma_rule)
    if filename.endswith(".ndjson"):
        with open(os.path.join(artifacts_path, filename), 'rb') as ndjson_file:
            files = {'file': (filename, ndjson_file, 'application/octet-stream')}
            print("Importing " + filename, end=": ")
            response = requests.post(url, headers=headers, auth=(username, password), files=files)
            if response.ok:
                response_json = json.loads(response.text)
                if response_json['success']:
                    print("Success")
                else:
                    print("Failed")
                    print(response.text)
                    exit_code = 1
sys.exit(exit_code)
