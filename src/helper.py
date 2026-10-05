# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""DNS lookup helpers."""

import ipaddress


def create_resolver(dns_server: str | None):
    """Create a dnspython resolver configured with the optional server."""
    from dns.resolver import Resolver

    resolver = Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    return resolver


def is_ip_address(value: str) -> bool:
    """Return whether value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def error_message(exc: Exception) -> str:
    """Format resolver errors in the legacy connector's familiar form."""
    args = exc.args
    error_code = "Error code unavailable"
    message = "Unknown error occurred. Please check the asset configuration and|or action parameters."
    if len(args) > 1:
        error_code, message = args[0], args[1]
    elif args:
        message = args[0]
    return f"Error Code: {error_code}. Error Message: {message}"
