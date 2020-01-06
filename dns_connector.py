# File: dns_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from dns_consts import *
import dns.resolver as resolver  # noqa
import dns.reversename as reversename  # noqa
import ipaddr  # noqa
import requests
import json


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
        self._server = config.get('dns_server')
        self._host_name = config.get('host_name', 'www.splunk.com')

        return phantom.APP_SUCCESS

    def _test_connectivity(self):
        dnslookup = resolver.Resolver()
        if self._server:
            dnslookup.nameservers = [self._server.encode("utf-8")]
            self.save_progress(
                "Checking connectivity to your defined lookup server ({0})...".format(str(dnslookup.nameservers[0])))
            try:
                dnslookup.lifetime = 5
                response = str(dnslookup.query(self._host_name, 'A')[0])
                self.save_progress("Found a record for {0} as {1}...".format(
                    self._host_name, response))
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to dns server was successful.")
            except Exception as e:
                self.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
                return self.get_status()
        else:
            self.save_progress(
                "Using OS level lookup server ({0})...".format(dnslookup.nameservers[0]))
            try:
                response = str(resolver.query(self._host_name, 'A')[0])
                self.save_progress("Found a record for {0} as {1}...".format(
                    self._host_name, response))
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to dns server was successful.")
            except Exception as e:
                self.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
                return self.get_status()

    def _handle_forward_lookup(self, param):

        # Add an action result to the Connector Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get the server
        server = self._server
        host = param['domain']
        type = 'A'
        if param.get('type'):
            type = param['type']

        try:
            dnslookup = resolver.Resolver()
            if (server):
                dnslookup.nameservers = [server]
            if not phantom.is_ip(host):
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
        host = param['ip']

        try:
            dnslookup = resolver.Resolver()
            if (server):
                dnslookup.nameservers = [server]
            if phantom.is_ip(host) or ipaddr.IPv6Address(host):
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
