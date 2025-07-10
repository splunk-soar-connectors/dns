# DNS

Publisher: Splunk \
Connector Version: 2.0.29 \
Product Vendor: Generic \
Product Name: DNS \
Minimum Product Version: 6.3.0

This app implements investigative actions that return DNS Records for the object queried

This simple DNS resolver app is designed to provide both forward and reverse lookup capabilities.
Users can specify a name and record type in a "lookup domain" action, or an IP address in a "lookup
ip" action. IPv4 and IPv6 addresses are both supported.

### Configuration variables

This table lists the configuration variables required to operate DNS. These variables are specified when configuring a DNS asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**dns_server** | optional | string | IP of the DNS server for lookups |
**host_name** | optional | string | Hostname to be used in test connectivity |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity \
[lookup domain](#action-lookup-domain) - Query DNS records for a Domain or Host Name \
[lookup ip](#action-lookup-ip) - Query Reverse DNS records for an IP

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'lookup domain'

Query DNS records for a Domain or Host Name

Type: **investigate** \
Read only: **True**

A list of record <b>types</b> to be resolved is supplied, one of which the user may choose as the value for the <b>type</b> parameter, these are:<br><ul><li>A</li><li>AAAA</li><li>CNAME</li><li>HINFO</li><li>ISDN</li><li>MX</li><li>NS</li><li>SOA</li><li>TXT</li></ul>When taking a lookup domain action from a Playbook, the author can look up arbitrary DNS record types by supplying the desired record type as a string for the <b>type</b> parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Record to resolve | string | `host name` `domain` |
**type** | optional | DNS Record Type | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `host name` `domain` | test.com |
action_result.parameter.type | string | | |
action_result.data.\*.record_info_objects.\*.record_info | string | `ip` | 122.122.122.122 |
action_result.data.\*.record_infos | string | `ip` | 122.122.122.122 |
action_result.summary.cannonical_name | string | | phantomtest.com. test.com. |
action_result.summary.canonical_name | string | | |
action_result.summary.hostname | string | `host name` `domain` | ffobaaar.com |
action_result.summary.record_info | string | `ip` | 122.122.122.122 |
action_result.summary.total_record_infos | numeric | | 1 6 |
action_result.message | string | | None of DNS query names exist: ['ffobaaar.com.', 'ffobaaar.com.localdomain.'] Record info: 54.239.25.192, Total record infos: 6, Cannonical name: amazon.com. |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ip'

Query Reverse DNS records for an IP

Type: **investigate** \
Read only: **True**

The <b>lookup ip</b> action takes an IP address parameter. The IP address (IPv4 or IPv6) will be looked up against the appropriate reverse lookup DNS records, and any associate hostname(s) will be returned. Only <b>PTR</b> type lookups are returned.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to resolve | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` | 122.122.122.122 123.123.123.123 |
action_result.data | string | | |
action_result.summary.cannonical_name | string | | 122.122.122.122.in-addr.arpa. |
action_result.summary.canonical_name | string | | |
action_result.summary.hostname | string | `host name` `domain` | ec2-52-91-186-198.compute-1.test.com. |
action_result.summary.ip | string | `ip` | 122.122.122.122 |
action_result.message | string | | Ip: 122.122.122.122 Hostname: ec2-52-91-186-198.compute-1.test.com. Cannonical name: 122.122.122.122.in-addr.arpa. The DNS query name does not exist: 123.123.123.123.in-addr.arpa. |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
