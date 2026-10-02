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
"""Reverse DNS lookup action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..consts import LOOKUP_QUERY_ERROR, TARGET_NOT_IP
from ..helper import create_resolver, error_message, is_ip_address


class LookupIpParams(Params):
    """Input parameter for a reverse DNS lookup."""

    ip: str = Param(
        description="IP to resolve", primary=True, required=True, cef_types=["ip"]
    )


class LookupIpOutput(PermissiveActionOutput):
    """Reverse lookup data with explicit values for the legacy data path and table."""

    data: str | None = OutputField(example_values=["dns.google."])


class LookupIpSummary(ActionOutput):
    """Reverse lookup summary fields in the original table order."""

    ip: str | None = OutputField(column_name="IP Address", cef_types=["ip"])
    hostname: str | None = OutputField(
        column_name="Hostname", cef_types=["host name", "domain"]
    )
    canonical_name: str | None = OutputField(alias="cannonical_name")
    canonical_name_corrected: str | None = OutputField(alias="canonical_name")


def lookup_ip(params: LookupIpParams, soar: SOARClient, asset) -> LookupIpOutput:
    """Resolve the PTR record for an IPv4 or IPv6 address."""
    from dns.reversename import from_address

    ip = params.ip
    if not is_ip_address(ip):
        raise ValueError(TARGET_NOT_IP)

    resolver = create_resolver(asset.dns_server)
    try:
        answer = resolver.resolve(from_address(ip), "PTR")
    except Exception as exc:
        message = error_message(exc)
        if "does not exist" in message:
            soar.set_message(message)
            return LookupIpOutput(data=None)
        raise RuntimeError(f"{LOOKUP_QUERY_ERROR}. Error string: '{exc}'") from exc

    hostname = str(answer[0]) if answer else None
    canonical_name = str(answer.canonical_name)
    soar.set_summary(
        LookupIpSummary(
            ip=ip,
            hostname=hostname,
            cannonical_name=canonical_name,
            canonical_name=None,
        )
    )
    soar.set_message(
        f"Ip: {ip}\nHostname: {hostname}\nCannonical name: {canonical_name}"
    )
    return LookupIpOutput(data=hostname)
