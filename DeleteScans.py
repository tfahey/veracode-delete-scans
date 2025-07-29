import argparse
import logging
import datetime
import os

import anticrlf
from veracode_api_py.api import VeracodeAPI as vapi, Applications, XMLAPI
from veracode_api_signing.credentials import get_credentials
import xml.etree.ElementTree as ET  # for parsing XML

log = logging.getLogger(__name__)

ALLOWED_ACTIONS = ['COMMENT', 'FP', 'APPDESIGN', 'OSENV', 'NETENV', 'REJECTED', 'ACCEPTED', 'LIBRARY', 'ACCEPTRISK', 
                   'APPROVE', 'REJECT', 'BYENV', 'BYDESIGN', 'LEGAL', 'COMMERCIAL', 'EXPERIMENTAL', 'INTERNAL', 'APPROVED']

class VeracodeApiCredentials():
    api_key_id = None
    api_key_secret = None

    def __init__(self, api_key_id, api_key_secret):
        self.api_key_id = api_key_id
        self.api_key_secret = api_key_secret

    def run_with_credentials(self, to_run):
        old_id = os.environ.get('veracode_api_key_id', "")
        old_secret = os.environ.get('veracode_api_key_secret', "")
        os.environ['veracode_api_key_id'] = self.api_key_id
        os.environ['veracode_api_key_secret'] = self.api_key_secret
        try:
            return to_run(None)
        finally:
            os.environ['veracode_api_key_id'] = old_id
            os.environ['veracode_api_key_secret'] = old_secret


def setup_logger():
    handler = logging.FileHandler('DeleteScans.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    log = logging.getLogger(__name__)
    log.addHandler(handler)
    log.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    # if (delta.days < 7):
    print('These API credentials expire ', creds['expiration_ts'])

def prompt_for_app(prompt_text):
    logprint('Prompting for app name to retrieve app id ')

    appname = ""
    appguid = ""
    app_id = 0
    app_name_search = input(prompt_text)

    logprint('Searching for app name {} '.format(app_name_search))
    app_candidates = Applications().get_by_name(app_name_search)
    logprint('Found {} candidates that match app name {} '.format(len(app_candidates),app_name_search))

    if len(app_candidates) == 0:
        print("No matches were found!")
    elif len(app_candidates) > 1:
        print("Please choose an application:")
        for idx, appitem in enumerate(app_candidates,start=1):
            print("{}) {}".format(idx, appitem["profile"]["name"]))
        i = input("Enter number: ")
        try:
                appname = app_candidates[int(i)-1]["profile"]["name"]
                appguid = app_candidates[int(i)-1].get('guid')
                app_id = app_candidates[int(i)-1].get('id')
        except ValueError:
            appguid = ""
            app_id = 0
    else:
        appname = app_candidates[0]["profile"]["name"]
        appguid = app_candidates[0].get('guid')
        app_id = app_candidates[0].get('id')

    logprint('For app name {} found id {}'.format(appname,app_id))
    return appname, app_id

def get_app_guid_from_legacy_id(app_id):
    app = Applications().get(legacy_id=app_id)
    if app is None:
        return
    return app['_embedded']['applications'][0]['guid']

def getBuildList(app_id):
    buildList = []
    buildList = XMLAPI.get_build_list(XMLAPI, app_id, None)

    return buildList

def getBuildInfo(app_id, build_id):
    buildInfo_XML = ""
    buildInfo_XML = XMLAPI.get_build_info(XMLAPI, app_id, build_id, None)

    return buildInfo_XML

def logprint(log_msg):
    log.info(log_msg)
    print(log_msg)

def get_exact_application_name_match(application_name, app_candidates):
    for application_candidate in app_candidates:
        if application_candidate["profile"]["name"] == application_name:
            return application_candidate["guid"]
    print("Unable to find application named " + application_name)
    return None

def get_application_by_name(application_name):
    app_candidates = Applications().get_by_name(application_name)
    if len(app_candidates) == 0:
        print("Unable to find application named " + application_name)
        return None
    elif len(app_candidates) > 1:
        return get_exact_application_name_match(application_name, app_candidates)
    else:
        return app_candidates[0].get('guid')

def get_application_guids_by_name(application_names):
    application_ids = []
    names_as_list = [application.strip() for application in application_names.split(", ")]

    for application_name in names_as_list:
        application_id = get_application_by_name(application_name)
        if application_id is not None:
            application_ids.append(application_id)

    return application_ids

def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM APP. For any flaws that have an '
                    'accepted mitigation, it checks the TO APP to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--app', help='App GUID to delete scans from')

    parser.add_argument('-fn', '--appname', help='Application Name to copy from')

    parser.add_argument('-p', '--prompt', action='store_true', help='Specify to prompt for the applications to copy from and to.')
    parser.add_argument('-d', '--dry_run', action='store_true', help="Log matched flaws instead of applying mitigations")
    parser.add_argument('-l', '--legacy_ids',action='store_true', help='Use legacy Veracode app IDs instead of GUIDs')

    parser.add_argument('-vid','--veracode_api_key_id', help='VERACODE_API_KEY_ID to use (if combined with --to_veracode_api_key_id and --to_veracode_api_key_secret, allows for moving mitigations between different instances of the platform)')
    parser.add_argument('-vkey','--veracode_api_key_secret', help='VERACODE_API_KEY_SECRET to use (if combined with --to_veracode_api_key_id and --to_veracode_api_key_secret, allows for moving mitigations between different instances of the platform)')

    args = parser.parse_args()

    setup_logger()

    logprint('======== beginning DeleteScans.py run ========')

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    app_id = args.app
    appname = args.appname
    prompt = args.prompt
    dry_run = args.dry_run
    legacy_ids = args.legacy_ids

    if args.veracode_api_key_id and args.veracode_api_key_secret:
        credentials = VeracodeApiCredentials(args.veracode_api_key_id, args.veracode_api_key_secret)
    else:
        api_key_id, api_key_secret = get_credentials()
        credentials = VeracodeApiCredentials(api_key_id, api_key_secret)

    if prompt:
        appname, app_id = credentials.run_with_credentials(lambda _:  prompt_for_app("Enter the application name to delete DAST scans from: "))
    else:
        if appname:
            app_id = credentials.run_with_credentials(lambda _: get_application_guids_by_name(appname)[0])

    if app_id in ( None, '' ):
        print('You must provide an application to delete DAST scans from.')
        return

    if legacy_ids:
        results_from = credentials.run_with_credentials(lambda _: get_app_guid_from_legacy_id(app_id))
        app_id = results_from

    build_list_XML = getBuildList(app_id)
    logprint("Build list retrieved for app_id {}".format(app_id))
    build_list = ET.fromstring(build_list_XML)
    logprint(build_list)

    dynamic_build_count = 0
    
    for build in build_list:
        build_id = build.get("build_id")
        logprint("Build ID {}".format(build_id))
        build_info_XML = getBuildInfo(app_id, build_id)
        buildInfo = ET.fromstring(build_info_XML)
        logprint("Build Info XML: {}".format(build_info_XML))
        logprint("Build Info: {}".format(buildInfo))
        logprint("Build Info Attribute: {}".format(buildInfo.attrib))

        logprint("Build Info Attribute has size: {}".format(len(buildInfo.attrib)))
        logprint("Build Info Attribute has type: {}".format(type(buildInfo.attrib)))

        for child in buildInfo.attrib:
            logprint("BuildInfo Attribute child: {}".format(child))
            logprint("BuildInfo Attribute child value: {}".format(buildInfo.attrib[child]))
            if child == 'dynamic_scan_type' and buildInfo.attrib[child] == 'ds':
                logprint("--------> We have a dynamic scan with build ID: {} <------------".format(build_id))
                dynamic_build_count += 1

        for child in buildInfo:
            logprint("BuildInfo child: {} attribute {}".format(child.tag, child.attrib))
            # child.tag, child.attrib

    if dynamic_build_count == 1:
        plural = ''
    else:
        plural = 's'
    logprint("--------> We found {} dynamic scan{} for app name {} and ID {} <------------".format(dynamic_build_count, plural, appname, app_id))

    logprint('======== ending DeleteScans.py run ========')

if __name__ == '__main__':
    main()
