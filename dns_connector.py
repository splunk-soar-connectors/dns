# --
# File: dns_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --
# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import os

# Imports local to this App
from dns_consts import *
app_dir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.insert(0, os.path.join(app_dir, 'dependencies/dnspython'))
import dns.resolver as resolver  # noqa
import dns.reversename as reversename  # noqa
import ipaddr  # noqa


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

        return phantom.APP_SUCCESS

    def _test_connectivity(self):
        dnslookup = resolver.Resolver()
        if self._server:
            dnslookup.nameservers = [self._server.encode("utf-8")]
            self.save_progress("Checking connectivity to your defined lookup server (" + str(dnslookup.nameservers[0]) + ")...")
            try:
                dnslookup.lifetime = 5
                response = str(dnslookup.query('www.phantom.us', 'A')[0])
                self.save_progress("Found a record for www.phantom.us as " + response + "...")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to dns server was successful.")
            except Exception as e:
                self.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
                return self.get_status()
        else:
            self.save_progress("Using OS level lookup server (" + dnslookup.nameservers[0] + ")...")
            try:
                response = str(resolver.query('www.phantom.us', 'A')[0])
                self.save_progress("Found a record for www.phantom.us as " + response + "...")
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
                ips = []
                dns_response = dnslookup.query(host, type)
                for item in dns_response:
                    ips.append(str(item))
                formed_results = {'total_ips': len(ips)}
                action_result.update_summary(formed_results)
                action_result.update_summary({'ip': str(dns_response[0])})
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(phantom.APP_ERROR, "Target is not a hostname")
                return action_result.get_status()
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, SAMPLEDNS_ERR_QUERY, e)
            return action_result.get_status()
        data = {'ips': ips}
        data['ip_objects'] = [{'ip': x} for x in ips]
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
                response = dnslookup.query(reversename.from_address(host), 'PTR')
                dns_response = str(response[0])
                formed_results = {'ip': host, 'hostname': dns_response}
                action_result.update_summary(formed_results)
                action_result.update_summary({'cannonical_name': str(response.canonical_name)})
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(phantom.APP_ERROR, "Target is not an IP")
                return action_result.get_status()
        except Exception as e:
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

    import sys
    import json

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DNSConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
