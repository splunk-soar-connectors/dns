[comment]: # "Auto-generated SOAR connector documentation"
# DNS

Publisher: Splunk  
Connector Version: 2\.0\.23  
Product Vendor: Generic  
Product Name: DNS  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app implements investigative actions that return DNS Records for the object queried

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
This simple DNS resolver app is designed to provide both forward and reverse lookup capabilities.
Users can specify a name and record type in a "lookup domain" action, or an IP address in a "lookup
ip" action. IPv4 and IPv6 addresses are both supported.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a DNS asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**dns\_server** |  optional  | string | IP of the DNS server for lookups
**host\_name** |  optional  | string | Hostname to be used in test connectivity

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[lookup domain](#action-lookup-domain) - Query DNS records for a Domain or Host Name  
[lookup ip](#action-lookup-ip) - Query Reverse DNS records for an IP  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup domain'
Query DNS records for a Domain or Host Name

Type: **investigate**  
Read only: **True**

A list of record <b>types</b> to be resolved is supplied, one of which the user may choose as the value for the <b>type</b> parameter, these are\:<br><ul><li>A</li><li>AAAA</li><li>CNAME</li><li>HINFO</li><li>ISDN</li><li>MX</li><li>NS</li><li>SOA</li><li>TXT</li></ul>When taking a lookup domain action from a Playbook, the author can look up arbitrary DNS record types by supplying the desired record type as a string for the <b>type</b> parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Record to resolve | string |  `host name`  `domain` 
**type** |  optional  | DNS Record Type | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `host name`  `domain` 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.record\_info\_objects\.\*\.record\_info | string |  `ip` 
action\_result\.data\.\*\.record\_infos | string |  `ip` 
action\_result\.summary\.cannonical\_name | string | 
action\_result\.summary\.canonical\_name | string | 
action\_result\.summary\.hostname | string |  `host name`  `domain` 
action\_result\.summary\.record\_info | string |  `ip` 
action\_result\.summary\.total\_record\_infos | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Query Reverse DNS records for an IP

Type: **investigate**  
Read only: **True**

The <b>lookup ip</b> action takes an IP address parameter\. The IP address \(IPv4 or IPv6\) will be looked up against the appropriate reverse lookup DNS records, and any associate hostname\(s\) will be returned\. Only <b>PTR</b> type lookups are returned\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to resolve | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data | string | 
action\_result\.summary\.cannonical\_name | string | 
action\_result\.summary\.canonical\_name | string | 
action\_result\.summary\.hostname | string |  `host name`  `domain` 
action\_result\.summary\.ip | string |  `ip` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 