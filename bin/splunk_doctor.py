#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exaplanation: splunk_doctor enables analysis of Splunk install in Sumo Logic

Usage:
   $ python  splunk_doctor [ options ]

Style:
   Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

    @name           splunk_doctor
    @version        1.00
    @author-name    Wayne Schmidt
    @author-email   wschmidt@sumologic.com
    @license-name   GNU GPL
    @license-url    http://www.gnu.org/licenses/gpl.html
"""

__version__ = 1.00
__author__ = "Wayne Schmidt (wschmidt@sumologic.com)"

### beginning ###
import configparser
import json
import pprint
import os
import re
import sys
import argparse
import http
import time
import requests

sys.dont_write_bytecode = 1

MY_CFG = 'undefined'
PARSER = argparse.ArgumentParser(description="""
splunk_doctor collects and analyzes vendor information within Sumo Logic
""")

PARSER.add_argument("-a", metavar='<secret>', dest='MY_SECRET', \
                    help="set api (format: <key>:<secret>) ")
PARSER.add_argument("-k", metavar='<client>', dest='MY_CLIENT', \
                    help="set key (format: <site>_<orgid>) ")
PARSER.add_argument("-e", metavar='<endpoint>', dest='MY_ENDPOINT', \
                    help="set endpoint (format: <endpoint>) ")
PARSER.add_argument("-d", metavar='<sourcedir>', dest='sourcedir', \
                    help="set data source (format: directory path)")
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
APP_MAPPING = dict()

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
    print('ERROR: Env Variable not set :: {} '.format(myerror.args[0]))

PPRINT = pprint.PrettyPrinter(indent=4)
PARSER = configparser.ConfigParser()

### beginning ###

def main():
    """
    Setup the Sumo API connection, using the required tuple of region, id, and key.
    Once done, then issue the command required
    """

    source = SumoApiClient(SUMO_UID, SUMO_KEY, SUMO_END)

    prepare_partition()

    collect_config_files(source)
    collect_applications(source)
    collect_user_history(source)

    perform_analysis()

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

def collect_applications(source):
    """
    This module collects information about applications from local and default files
    """

    if ARGS.verbose > 2:
        print("STEP-1.3.0 :: Collector: Create hosted collectors for applications")
        print("STEP-1.3.1 :: Config_Files: Collect all application files from system")
        print("STEP-1.3.2 :: Config_Files: Stored as one application per source")

    cl_name = 'splunk_applications_history'
    src_category = 'splunk/applications/history'
    parentid = source.create_collector(cl_name, src_category)['collector']['id']

    if ARGS.sourcedir:
        for root, _dirs, files in os.walk(ARGS.sourcedir):
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
            APP_MAPPING[s_base] = dict()
        if not s_value in APP_MAPPING[s_base]:
            APP_MAPPING[s_base][s_value] = dict()
        APP_MAPPING[s_base][s_value] = os.path.getmtime(src_file)
        src_name = s_base + '_' + s_value
        source_output = source.create_source(parentid, src_name, src_category)
        src_url = (source_output['source']['url'])
        post_application_files(src_name, src_category, src_file, src_url)

def post_app_manifest(source):
    """
    Post the manifest of applications to Sumo Logic
    """
    session = requests.Session()

    cl_name = 'splunk_applications_manifest'
    src_category = 'splunk/applications/manifest'
    parentid = source.create_collector(cl_name, src_category)['collector']['id']

    for app_key in APP_MAPPING:

        src_name = app_key
        source_output = source.create_source(parentid, src_name, src_category)
        src_url = (source_output['source']['url'])

        headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : app_key}
        status_code = session.post(src_url, APP_MAPPING[app_key], headers=headers).status_code

        if ARGS.verbose > 3:
            print('OBJECT: {}'.format(app_key))
        if ARGS.verbose > 5:
            print('RESPONSE: {}'.format(status_code))

def post_application_files(src_name, src_category, src_file, src_url):
    """
    Read and post the contents of the file into a message
    If the config file is valid then split by section. If not read as one message
    """
    if ARGS.verbose > 4:
        print('OBJECT: {} {}'.format(src_name, src_category))

    time.sleep(WAIT_TIME)

    session = requests.Session()
    with open(src_file, mode='r') as uploadobject:
        try:
            PARSER.read(src_file)
            confdict = {section: dict(PARSER.items(section)) for section in PARSER.sections()}
            for item in confdict:
                headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
                status_code = session.post(src_url, confdict[item], headers=headers).status_code
                if ARGS.verbose > 5:
                    print('RESPONSE: {}'.format(status_code))
        except:
            msg_contents = (uploadobject.read().encode('utf-8'))
            headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
            status_code = session.post(src_url, msg_contents, headers=headers).status_code
            if ARGS.verbose > 5:
                print('RESPONSE: {}'.format(status_code))

def collect_config_files(source):
    """
    This module collects vendor configuration files
    """

    if ARGS.verbose > 2:
        print("STEP-1.2.0 :: Collector: Create a hosted collector for config files")
    cl_name = 'splunk_configs'
    src_category = 'splunk/configs'
    parentid = source.create_collector(cl_name, src_category)['collector']['id']

    if ARGS.verbose > 2:
        print("STEP-1.2.1 :: Config_Files: Collect all configuration files from system")
        print("STEP-1.2.2 :: Config_Files: Stored as one configuration per source")

    src_file_map = dict()
    if ARGS.sourcedir:
        for root, _dirs, files in os.walk(ARGS.sourcedir):
            for file in files:
                src_file = (os.path.join(root, file))
                regex = re.compile(r".*\/etc\/system\/.*.conf$")
                if regex.match(src_file):
                    source_match = re.match(r".*etc\/system\/(.*)", src_file)
                    src_name = source_match.groups()[0]
                    source_output = source.create_source(parentid, src_name, src_category)
                    src_url = (source_output['source']['url'])
                    src_file_map[src_file] = src_name
                    post_config_files(src_name, src_category, src_file, src_url)

    if ARGS.verbose > 8:
        print('MAPPING:')
        PPRINT.pprint(src_file_map)

def post_config_files(src_name, src_category, src_file, src_url):
    """
    Read and post the contents of the file into a message
    If the config file is valid then split by section. If not read as one message
    """
    if ARGS.verbose > 4:
        print('OBJECT: {} {}'.format(src_name, src_category))

    time.sleep(WAIT_TIME)

    session = requests.Session()
    with open(src_file, mode='r') as uploadobject:
        try:
            PARSER.read(src_file)
            confdict = {section: dict(PARSER.items(section)) for section in PARSER.sections()}
            for item in confdict:
                headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
                status_code = session.post(src_url, confdict[item], headers=headers).status_code
                if ARGS.verbose > 5:
                    print('RESPONSE: {}'.format(status_code))
        except:
            msg_contents = (uploadobject.read().encode('utf-8'))
            headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
            status_code = session.post(src_url, msg_contents, headers=headers).status_code
            if ARGS.verbose > 5:
                print('RESPONSE: {}'.format(status_code))

def collect_user_history(source):
    """
    This module collects the files from user history and uploads them into sources
    """
    if ARGS.verbose > 2:
        print("STEP-1.4.0 :: Collector: Create a hosted collector for history files")
        print("STEP-1.4.1 :: Data_Sources: Collect all files in ./etc/users/ANYUSER/history")
        print("STEP-1.4.2 :: Data_Sources: stored as one file per source")

    cl_name = 'splunk_history'
    src_category = 'splunk/usage/history'
    parentid = source.create_collector(cl_name, src_category)['collector']['id']

    src_file_map = dict()
    if ARGS.sourcedir:
        for root, _dirs, files in os.walk(ARGS.sourcedir):
            for file in files:
                src_file = (os.path.join(root, file))
                regex = re.compile(r".*\/history\/.*.csv")
                if regex.match(src_file):
                    source_match = re.match(r".*users\/(.*)\/history.*", src_file)
                    src_name = source_match.groups()[0]
                    source_output = source.create_source(parentid, src_name, src_category)
                    src_url = (source_output['source']['url'])
                    src_file_map[src_file] = src_name
                    post_history_files(src_name, src_category, src_file, src_url)

    if ARGS.verbose > 8:
        print('MAPPING:')
        PPRINT.pprint(src_file_map)

def post_history_files(src_name, src_category, src_file, src_url):
    """
    Read and post the contents of the file into a message
    Later provide post processing on the schema used for the file
    """
    if ARGS.verbose > 4:
        print('OBJECT: {} {}'.format(src_name, src_category))

    time.sleep(WAIT_TIME)

    with open(src_file, mode='r') as uploadfile:
        slrfmap8 = (uploadfile.read().encode('utf-8'))
        headers = {'Content-Type':'txt/csv', 'X-Sumo-Name' : src_name}
        session = requests.Session()
        status_code = session.post(src_url, slrfmap8, headers=headers).status_code
    if ARGS.verbose > 5:
        print('RESPONSE: {}'.format(status_code))

### class ###
class SumoApiClient():
    """
    This is defined SumoLogic API Client
    The class includes the HTTP methods, cmdlets, and init methods
    """

    def __init__(self, access_id, access_key, region, cookieFile='cookies.txt'):
        """
        Initializes the Sumo Logic object
        """
        self.session = requests.Session()
        self.session.auth = (access_id, access_key)
        self.session.headers = {'content-type': 'application/json', \
            'accept': 'application/json'}
        self.endpoint = 'https://api.' + region + '.sumologic.com/api'
        cookiejar = http.cookiejar.FileCookieJar(cookieFile)
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

    def create_collector(self, name, source_category):
        """
        Using an HTTP client, this creates a collector
        """

        object_type = 'collector'
        jsonpayload = {
            "api.version":"v1",
            "collector":{
                "name": name,
                "category": source_category,
                "timeZone":"Etc/UTC",
                "fields":{
                },
                "collectorType":"Hosted",
                "collectorVersion":""
            }
        }

        if ARGS.jsonfile:
            fileobject = open(ARGS.jsonfile, "r")
            jsonpayload = json.loads(fileobject.read())

        if ARGS.verbose > 8:
            print('JSONPAYLOAD: {}'.format(jsonpayload))

        if ARGS.overrides:
            for override in ARGS.overrides:
                or_key, or_value = override.split('=')
                jsonpayload[object_type][or_key] = or_value

        time.sleep(WAIT_TIME)

        if ARGS.verbose > 8:
            print('JSONPAYLOAD: {}'.format(jsonpayload))

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
            print('JSONPAYLOAD: {}'.format(jsonpayload))

        url = "/v1/collectors/" + str(parentid) + "/sources"
        body = self.post(url, jsonpayload).text
        results = json.loads(body)
        return results

### methods ###

if __name__ == '__main__':
    main()
