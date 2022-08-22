#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=W0702
# pylint: disable=R0914

"""
Explanation: sumologic_spelunker analyzes a Splunk Diag File in Sumo Logic

Usage:
   $ python  sumologic_spelunker [ options ]

Style:
   Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

    @name           sumologic_spelunker
    @version        3.00
    @author-name    Wayne Schmidt
    @author-email   wschmidt@sumologic.com
    @license-name   Apache 2.0
    @license-url    https://www.apache.org/licenses/LICENSE-2.0
"""

__version__ = 3.00
__author__ = "Wayne Schmidt (wschmidt@sumologic.com)"

### beginning ###
import configparser
import json
import os
import re
import sys
import argparse
import http
import time
import shutil
import tarfile
import requests

sys.dont_write_bytecode = 1

MY_CFG = 'undefined'
PARSER = argparse.ArgumentParser(description="""
sumologic_spelunker collects and analyzes vendor information within Sumo Logic
""")

PARSER.add_argument("-a", metavar='<secret>', dest='MY_SECRET', \
                    help="set api (format: <key>:<secret>) ")
PARSER.add_argument("-k", metavar='<client>', dest='MY_CLIENT', \
                    help="set key (format: <site>_<orgid>) ")
PARSER.add_argument("-e", metavar='<endpoint>', dest='MY_ENDPOINT', \
                    help="set endpoint (format: <endpoint>) ")
PARSER.add_argument("-s", metavar='<datasource>', dest='datasource', \
                    help="set data source (format: directory or file)")
PARSER.add_argument("-v", type=int, default=0, metavar='<verbose>', \
                    dest='verbose', help="increase verbosity")
PARSER.add_argument("-j", metavar='<jsonfile>', \
                    dest='jsonfile', help="specify the json payload")
PARSER.add_argument("-o", metavar='<overrides>', action='append', \
                    dest='overrides', help="specify override (format: key=value )")

ARGS = PARSER.parse_args()

LIMIT = 10000
LONGQUERY_LIMIT = 100
WAIT_TIME = 0.2
POST_TIME = 0.01
APP_MAPPING = {}

if ARGS.MY_SECRET:
    (MY_APINAME, MY_APISECRET) = ARGS.MY_SECRET.split(':')
    os.environ['SUMO_UID'] = MY_APINAME
    os.environ['SUMO_KEY'] = MY_APISECRET

if ARGS.MY_CLIENT:
    (MY_DEPLOYMENT, MY_ORGID) = ARGS.MY_CLIENT.split('_')
    os.environ['SUMO_LOC'] = MY_DEPLOYMENT
    os.environ['SUMO_ORG'] = MY_ORGID
    os.environ['SUMO_TAG'] = ARGS.MY_CLIENT

if ARGS.MY_ENDPOINT:
    os.environ['SUMO_END'] = ARGS.MY_ENDPOINT
else:
    os.environ['SUMO_END'] = os.environ['SUMO_LOC']

try:
    SUMO_UID = os.environ['SUMO_UID']
    SUMO_KEY = os.environ['SUMO_KEY']
    SUMO_LOC = os.environ['SUMO_LOC']
    SUMO_ORG = os.environ['SUMO_ORG']
    SUMO_END = os.environ['SUMO_END']
except KeyError as myerror:
    print(f'ERROR: Env Variable not set :: {myerror.args[0]}')

PARSER = configparser.ConfigParser()

SPLUNKHOST = os.path.basename(ARGS.datasource).split('-')[1]
EXTRACT_PATH = '/var/tmp'

### beginning ###

def main():
    """
    Setup the Sumo API connection, using the required tuple of region, id, and key.
    Once done, then issue the command required
    """

    source = SumoApiClient(SUMO_UID, SUMO_KEY, SUMO_END)

    source_image = resolve_datasource(ARGS.datasource)

    prepare_partition()

    collect_config_files(source, source_image)
    collect_applications(source, source_image)
    collect_user_history(source, source_image)

    perform_analysis()

def resolve_datasource(datatarget):
    """
    This unpacks the directory if given a diagnostic file
    """

    if os.path.isfile(datatarget):
        with tarfile.open(datatarget, mode='r', encoding='utf8') as archive_object:
            extract_dir = (os.path.commonprefix(archive_object.getnames()))
            shutil.unpack_archive(datatarget, EXTRACT_PATH)
            datasource = os.path.abspath(os.path.join(EXTRACT_PATH, extract_dir))
    else:
        datasource = os.path.abspath(datatarget)

    if ARGS.verbose > 3:
        print(f'{datasource}')

    return datasource

def prepare_partition():
    """
    This module first builds a new partition and then a hosted collector
    """

    if ARGS.verbose > 2:
        print("STEP-1.1.0 :: Partition: Create a partition to handle all routing")

def perform_analysis():
    """
    This module runs queries to analyze data
    """
    if ARGS.verbose > 2:
        print("STEP-1.5.1 :: Perform_Analysis: run all default Sumo Logic queries")
        print("STEP-1.5.2 :: Perform_Analysis: run all specified Sumo Logic queries")

def collect_applications(source, source_image):
    """
    This module collects information about applications from local and default files
    """

    if ARGS.verbose > 2:
        print("STEP-1.3.0 :: Collector: Create hosted collectors for applications")
        print("STEP-1.3.1 :: Config_Files: Collect all application files from system")
        print("STEP-1.3.2 :: Config_Files: Stored as one application per source")

    cl_name = 'splunk_applications_object_rbac'
    src_category = f'{"splunk"}/{SPLUNKHOST}/{"applications"}/{"objectrbac"}'

    src_items = source.get_collectors()
    parentid = 'undefined'

    for src_item in src_items:
        if str(src_item['name']) == cl_name:
            parentid = src_item['id']
    if parentid == 'undefined':
        parentid = source.create_collector(cl_name)['collector']['id']

    for root, _dirs, files in os.walk(source_image):
        for file in files:
            src_file = (os.path.join(root, file))
            regex = re.compile(r".*\/etc\/apps\/.*.meta$")
            if regex.match(src_file):
                source_match = re.match(r".*etc\/apps\/(.*)", src_file)
                post_app_history(source, source_match, src_file, parentid, src_category)

    post_app_manifest(source)

def post_app_history(source, source_match, src_file, parentid, src_category):
    """
    Post the history of changes for installed application to Sumo Logic
    """

    src_name = source_match.groups()[0]
    s_list = src_name.split('/')
    if (len(s_list)) == 3:
        s_base = s_list[0]
        s_value = s_list[-1].replace('.meta', '')
        if not s_base in APP_MAPPING:
            APP_MAPPING[s_base] = {}
        if not s_value in APP_MAPPING[s_base]:
            APP_MAPPING[s_base][s_value] = {}
        APP_MAPPING[s_base][s_value] = os.path.getmtime(src_file)
        src_name = SPLUNKHOST + '_' + s_base + '_' + s_value
        source_output = source.create_source(parentid, src_name, src_category)
        src_url = (source_output['source']['url'])
        post_application_files(src_name, src_category, src_file, src_url)

def post_app_manifest(source):
    """
    Post the manifest of applications to Sumo Logic
    """
    session = requests.Session()

    cl_name = 'splunk_applications_manifest'
    src_category = f'{"splunk"}/{SPLUNKHOST}/{"applications"}/{"manifest"}'

    src_items = source.get_collectors()
    parentid = 'undefined'

    for src_item in src_items:
        if str(src_item['name']) == cl_name:
            parentid = src_item['id']
    if parentid == 'undefined':
        parentid = source.create_collector(cl_name)['collector']['id']

    for app_key,app_value in APP_MAPPING.items():

        src_name = SPLUNKHOST + '_' + app_key
        source_output = source.create_source(parentid, src_name, src_category)
        src_url = (source_output['source']['url'])

        headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : app_key}
        status_code = session.post(src_url, app_value, headers=headers).status_code

        if ARGS.verbose > 3:
            print(f'OBJECT: {app_key}')
        if ARGS.verbose > 5:
            print(f'RESPONSE: {status_code}')

def post_application_files(src_name, src_category, src_file, src_url):
    """
    Read and post the contents of the file into a message
    If the config file is valid then split by section. If not read as one message
    """
    if ARGS.verbose > 4:
        print(f'OBJECT: {src_name} {src_category}')

    time.sleep(WAIT_TIME)

    session = requests.Session()
    with open(src_file, mode='r', encoding='utf8') as uploadobject:
        try:
            PARSER.read(src_file)
            confdict = {section: dict(PARSER.items(section)) for section in PARSER.sections()}
            for item in confdict:
                headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
                status_code = session.post(src_url, confdict[item], headers=headers).status_code
                if ARGS.verbose > 5:
                    print(f'RESPONSE: {status_code}')
        except:
            msg_contents = (uploadobject.read().encode('utf-8'))
            headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
            status_code = session.post(src_url, msg_contents, headers=headers).status_code
            if ARGS.verbose > 5:
                print(f'RESPONSE: {status_code}')

def collect_config_files(source, source_image):
    """
    This module collects vendor configuration files
    """

    if ARGS.verbose > 2:
        print("STEP-1.2.0 :: Collector: Create a hosted collector for config files")
    cl_name = 'splunk_configs'
    src_category = f'{"splunk"}/{SPLUNKHOST}/{"configs"}'

    src_items = source.get_collectors()
    parentid = 'undefined'

    for src_item in src_items:
        if str(src_item['name']) == cl_name:
            parentid = src_item['id']
    if parentid == 'undefined':
        parentid = source.create_collector(cl_name)['collector']['id']

    if ARGS.verbose > 2:
        print("STEP-1.2.1 :: Config_Files: Collect all configuration files from system")
        print("STEP-1.2.2 :: Config_Files: Stored as one configuration per source")

    src_file_map = {}
    for root, _dirs, files in os.walk(source_image):
        for file in files:
            src_file = (os.path.join(root, file))
            regex = re.compile(r".*\/etc\/system\/.*.conf$")
            if regex.match(src_file):
                source_match = re.match(r".*etc\/system\/(.*)", src_file)
                src_name = SPLUNKHOST + '_' + source_match.groups()[0]
                source_output = source.create_source(parentid, src_name, src_category)
                src_url = (source_output['source']['url'])
                src_file_map[src_file] = src_name
                post_config_files(src_name, src_category, src_file, src_url)

def post_config_files(src_name, src_category, src_file, src_url):
    """
    Read and post the contents of the file into a message
    If the config file is valid then split by section. If not read as one message
    """
    if ARGS.verbose > 4:
        print(f'OBJECT: {src_name} {src_category}')

    time.sleep(WAIT_TIME)

    session = requests.Session()
    with open(src_file, mode='r', encoding='utf8') as uploadobject:
        try:
            PARSER.read(src_file)
            confdict = {section: dict(PARSER.items(section)) for section in PARSER.sections()}
            for item in confdict:
                headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
                status_code = session.post(src_url, confdict[item], headers=headers).status_code
                if ARGS.verbose > 5:
                    print(f'RESPONSE: {status_code}')
        except:
            msg_contents = (uploadobject.read().encode('utf-8'))
            headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
            status_code = session.post(src_url, msg_contents, headers=headers).status_code
            if ARGS.verbose > 5:
                print(f'RESPONSE: {status_code}')

def collect_user_history(source, source_image):
    """
    This module collects the files from user history and uploads them into sources
    """
    if ARGS.verbose > 2:
        print("STEP-1.4.0 :: Collector: Create a hosted collector for history files")
        print("STEP-1.4.1 :: Data_Sources: Collect all files in ./etc/users/ANYUSER/history")
        print("STEP-1.4.2 :: Data_Sources: stored as one file per source")

    cl_name = 'splunk_history'
    src_category = f'{"splunk"}/{SPLUNKHOST}/{"usage"}/{"history"}'

    src_items = source.get_collectors()
    parentid = 'undefined'

    for src_item in src_items:
        if str(src_item['name']) == cl_name:
            parentid = src_item['id']
    if parentid == 'undefined':
        parentid = source.create_collector(cl_name)['collector']['id']

    src_file_map = {}
    for root, _dirs, files in os.walk(source_image):
        for file in files:
            src_file = (os.path.join(root, file))
            regex = re.compile(r".*\/history\/.*.csv")
            if regex.match(src_file):
                source_match = re.match(r".*users\/(.*)\/history.*", src_file)
                src_name = SPLUNKHOST + '_' + source_match.groups()[0]
                source_output = source.create_source(parentid, src_name, src_category)
                src_url = (source_output['source']['url'])
                src_file_map[src_file] = src_name
                post_history_files(src_name, src_category, src_file, src_url)

def post_history_files(src_name, src_category, src_file, src_url):
    """
    Read and post the contents of the file into a message
    Later provide post processing on the schema used for the file
    """
    if ARGS.verbose > 4:
        print(f'OBJECT: {src_name} {src_category}')

    time.sleep(POST_TIME)

    with open(src_file, mode='r', encoding='utf8' ) as uploadfile:
        slrfmap8 = (uploadfile.read().encode('utf-8'))
        headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
        session = requests.Session()
        status_code = session.post(src_url, slrfmap8, headers=headers).status_code
    if ARGS.verbose > 5:
        print(f'RESPONSE: {status_code}')

### class ###
class SumoApiClient():
    """
    This is defined SumoLogic API Client
    The class includes the HTTP methods, cmdlets, and init methods
    """

    def __init__(self, access_id, access_key, region, cookie_file='cookies.txt'):
        """
        Initializes the Sumo Logic object
        """
        self.session = requests.Session()
        self.session.auth = (access_id, access_key)
        self.session.headers = {'content-type': 'application/json', \
            'accept': 'application/json'}
        self.endpoint = 'https://api.' + region + '.sumologic.com/api'
        cookiejar = http.cookiejar.FileCookieJar(cookie_file)
        self.session.cookies = cookiejar

    def delete(self, method, params=None, headers=None, data=None):
        """
        Defines a Sumo Logic Delete operation
        """
        response = self.session.delete(self.endpoint + method, \
            params=params, headers=headers, data=data)
        if response.status_code != 200:
            response.reason = response.text
        response.raise_for_status()
        return response

    def get(self, method, params=None, headers=None):
        """
        Defines a Sumo Logic Get operation
        """
        response = self.session.get(self.endpoint + method, \
            params=params, headers=headers)
        if response.status_code != 200:
            response.reason = response.text
        response.raise_for_status()
        return response

    def post(self, method, data, headers=None, params=None):
        """
        Defines a Sumo Logic Post operation
        """
        response = self.session.post(self.endpoint + method, \
            data=json.dumps(data), headers=headers, params=params)
        if response.status_code != 200:
            response.reason = response.text
        response.raise_for_status()
        return response

    def put(self, method, data, headers=None, params=None):
        """
        Defines a Sumo Logic Put operation
        """
        response = self.session.put(self.endpoint + method, \
            data=json.dumps(data), headers=headers, params=params)
        if response.status_code != 200:
            response.reason = response.text
        response.raise_for_status()
        return response

### class ###
### methods ###

    def create_collector(self, name):
        """
        Using an HTTP client, this creates a collector
        """

        object_type = 'collector'
        jsonpayload = {
            "api.version":"v1",
            "collector":{
                "name": name,
                "timeZone":"Etc/UTC",
                "fields":{
                },
                "collectorType":"Hosted",
                "collectorVersion":""
            }
        }

        if ARGS.jsonfile:
            with open (ARGS.jsonfile, "r", encoding='utf8') as fileobject:
                jsonpayload = json.loads(fileobject.read())

        if ARGS.verbose > 8:
            print(f'JSONPAYLOAD: {jsonpayload}')

        if ARGS.overrides:
            for override in ARGS.overrides:
                or_key, or_value = override.split('=')
                jsonpayload[object_type][or_key] = or_value

        time.sleep(WAIT_TIME)

        if ARGS.verbose > 8:
            print(f'JSONPAYLOAD: {jsonpayload}')

        url = "/v1/collectors"
        body = self.post(url, jsonpayload).text
        results = json.loads(body)
        return results

    def create_source(self, parentid, name, category):
        """
        Using an HTTP client, this creates a source for a collector
        """
        jsonpayload = {
            "api.version": "v1",
            "source":{
                "name": name,
                "description": name,
                "category": category,
                "encoding":"UTF-8",
                "sourceType":"HTTP",
                "automaticDateParsing": True,
                "multilineProcessingEnabled": True,
                "useAutolineMatching": True,
                "forceTimeZone": False,
                "messagePerRequest": False
            }
        }

        time.sleep(WAIT_TIME)

        if ARGS.verbose > 8:
            print(f'JSONPAYLOAD: {jsonpayload}')

        url = "/v1/collectors/" + str(parentid) + "/sources"
        body = self.post(url, jsonpayload).text
        results = json.loads(body)
        return results

    def get_collectors(self):
        """
        Using an HTTP client, this uses a GET to retrieve all collector information.
        """
        url = "/v1/collectors"
        body = self.get(url).text
        results = json.loads(body)['collectors']
        return results

### methods ###

if __name__ == '__main__':
    main()
