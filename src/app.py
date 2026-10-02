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
"""Splunk SOAR SDK app for DNS lookups."""

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

from .actions.lookup_domain import (
    LookupDomainOutput,
    LookupDomainParams,
    LookupDomainSummary,
    display_domain_results,
    lookup_domain,
)
from .actions.lookup_ip import (
    LookupIpOutput,
    LookupIpParams,
    LookupIpSummary,
    lookup_ip,
)
from .consts import APP_NAME

logger = getLogger()


class Asset(BaseAsset):
    """DNS resolver configuration."""

    dns_server: str | None = AssetField(
        description="IP of the DNS server for lookups",
        required=False,
        default=None,
        category=FieldCategory.CONNECTIVITY,
    )
    host_name: str = AssetField(
        description="Hostname to be used in test connectivity",
        default="www.splunk.com",
        category=FieldCategory.CONNECTIVITY,
    )


app = App(
    name=APP_NAME,
    app_type="information",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Generic",
    product_name="DNS",
    publisher="Splunk",
    appid="876ab991-313e-48e7-bccd-e8c9650c239c",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Resolve the configured test hostname using the asset's DNS server."""
    from dns.resolver import Resolver

    resolver = Resolver()
    if asset.dns_server:
        resolver.nameservers = [asset.dns_server]
        soar.set_progress(
            f"Checking connectivity to your defined lookup server ({asset.dns_server})..."
        )
    else:
        soar.set_progress(
            f"Using OS level lookup server ({resolver.nameservers[0]})..."
        )

    try:
        resolver.lifetime = 5
        answer = str(resolver.resolve(asset.host_name, "A")[0])
    except Exception as exc:
        soar.set_progress("Test Connectivity Failed")
        raise RuntimeError("Lookup query failed") from exc

    soar.set_progress(f"Found a record for {asset.host_name} as {answer}...")
    soar.set_progress("Test Connectivity Passed")
    soar.set_message("Connectivity to dns server was successful.")


app.register_action(
    lookup_domain,
    name="lookup domain",
    identifier="forward_lookup",
    description="Query DNS records for a Domain or Host Name",
    verbose="A list of record <b>types</b> to be resolved is supplied, one of which the user may choose as the value for the <b>type</b> parameter, these are:<br><ul><li>A</li><li>AAAA</li><li>CNAME</li><li>HINFO</li><li>ISDN</li><li>MX</li><li>NS</li><li>SOA</li><li>TXT</li></ul>When taking a lookup domain action from a Playbook, the author can look up arbitrary DNS record types by supplying the desired record type as a string for the <b>type</b> parameter.",
    action_type="investigate",
    read_only=True,
    params_class=LookupDomainParams,
    output_class=LookupDomainOutput,
    summary_type=LookupDomainSummary,
    view_handler=display_domain_results,
    view_template="display_ip.html",
)

app.register_action(
    lookup_ip,
    name="lookup ip",
    identifier="reverse_lookup",
    description="Query Reverse DNS records for an IP",
    verbose="The <b>lookup ip</b> action takes an IP address parameter. The IP address (IPv4 or IPv6) will be looked up against the appropriate reverse lookup DNS records, and any associate hostname(s) will be returned. Only <b>PTR</b> type lookups are returned.",
    action_type="investigate",
    read_only=True,
    params_class=LookupIpParams,
    output_class=LookupIpOutput,
    summary_type=LookupIpSummary,
    render_as="table",
)


if __name__ == "__main__":
    app.cli()
