# File: dns_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from bs4 import UnicodeDammit
from dns_consts import *
import dns.resolver as resolver  # noqa
import dns.reversename as reversename  # noqa
import ipaddress  # noqa
import requests
import json
import sys

from builtins import str


# Define the App Class
class DNSConnector(BaseConnector):
    ACTION_ID_FORWARD_LOOKUP = "forward_lookup"
    ACTION_ID_REVERSE_LOOKUP = "reverse_lookup"

    def validate_parameters(self, param):
        """This app does it's own validation
        """
        return phantom.APP_SUCCESS

    def initialize(self):

        config = self.get_config()
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom "
                                                      "server's Python major version.")
        self._server = self._handle_py_ver_compat_for_input_str(config.get('dns_server'))
        self._host_name = self._handle_py_ver_compat_for_input_str(config.get('host_name', 'www.splunk.com'))

        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, input_str):

        """
        This method returns the encoded|original string based on the Python version.

        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str -
        Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _is_ip(self, input_ip_address):

        """
        Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """
        ip_address_input = input_ip_address
        try:
            ipaddress.ip_address(UnicodeDammit(ip_address_input).unicode_markup)
        except:
            return False
        return True

    def _test_connectivity(self):
        dnslookup = resolver.Resolver()
        if self._server:
            dnslookup.nameservers = [self._handle_py_ver_compat_for_input_str(self._server)]

            if dnslookup.nameservers:
                self.save_progress("Checking connectivity to your defined lookup server ({0})...".format
                                   (dnslookup.nameservers[0]))
            try:
                dnslookup.lifetime = 5
                response = str(dnslookup.query(self._host_name, 'A')[0])
                self.save_progress("Found a record for {0} as {1}...".format(
                    self._host_name, response))
                self.save_progress("Test connectivity passed")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to dns server was successful.")
            except Exception as e:
                self.save_progress("Test connectivity failed")
                self.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
                return self.get_status()
        else:
            self.save_progress(
                "Using OS level lookup server ({0})...".format(dnslookup.nameservers[0]))
            try:
                response = str(resolver.query(self._host_name, 'A')[0])
                self.save_progress("Found a record for {0} as {1}...".format(
                    self._host_name, response))
                self.save_progress("Test connectivity passed")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to dns server was successful.")
            except Exception as e:
                self.save_progress("Test connectivity failed")
                self.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
                return self.get_status()

    def _handle_forward_lookup(self, param):

        # Add an action result to the Connector Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get the server
        server = self._server
        host = self._handle_py_ver_compat_for_input_str(param['domain'])
        type = 'A'
        if param.get('type'):
            type = self._handle_py_ver_compat_for_input_str(param['type'])

        try:
            dnslookup = resolver.Resolver()
            if (server):
                dnslookup.nameservers = [server]
            if not self._is_ip(host):
                record_infos = []
                dns_response = dnslookup.query(host, type)
                for item in dns_response:
                    record_infos.append(str(item))
                formed_results = {'total_record_infos': len(record_infos)}
                action_result.update_summary(formed_results)
                try:
                    action_result.update_summary(
                        {'cannonical_name': str(dns_response.canonical_name)})
                    action_result.update_summary(
                        {'record_info': str(dns_response[0])})
                except:
                    pass
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(
                    phantom.APP_ERROR, "Target is not a hostname")
                return action_result.get_status()
        except Exception as e:
            if ('None of DNS query names exist' in str(e)):
                return action_result.set_status(phantom.APP_SUCCESS, str(e))
            action_result.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
            return action_result.get_status()
        data = {'record_infos': record_infos}
        data['record_info_objects'] = [
            {'record_info': x} for x in record_infos]
        action_result.add_data(data)

        return action_result.get_status()

    def _handle_reverse_lookup(self, param):

        # Add an action result to the Connector Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get the server
        server = self._server
        host = self._handle_py_ver_compat_for_input_str(param['ip'])

        try:
            dnslookup = resolver.Resolver()
            if (server):
                dnslookup.nameservers = [server]
            if self._is_ip(host):  # changed module
                response = dnslookup.query(
                    reversename.from_address(host), 'PTR')
                dns_response = str(response[0])
                formed_results = {'ip': host, 'hostname': dns_response}
                action_result.update_summary(formed_results)
                action_result.update_summary(
                    {'cannonical_name': str(response.canonical_name)})
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(
                    phantom.APP_ERROR, "Target is not an IP")
                return action_result.get_status()
        except Exception as e:
            if ('does not exist' in str(e)):
                return action_result.set_status(phantom.APP_SUCCESS, str(e))
            action_result.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
            return action_result.get_status()

        action_result.add_data(dns_response)

        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_FORWARD_LOOKUP):
            ret_val = self._handle_forward_lookup(param)
        elif (action_id == self.ACTION_ID_REVERSE_LOOKUP):
            ret_val = self._handle_reverse_lookup(param)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + 'login'
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DNSConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
