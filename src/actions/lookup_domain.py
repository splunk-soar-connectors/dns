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
"""Forward DNS lookup action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    ActionResult,
    OutputField,
)
from soar_sdk.params import Param, Params

from ..consts import LOOKUP_QUERY_ERROR, TARGET_NOT_HOSTNAME
from ..helper import create_resolver, error_message, is_ip_address


class LookupDomainParams(Params):
    """Input parameters for a forward DNS lookup."""

    domain: str = Param(
        description="Record to resolve",
        primary=True,
        required=True,
        cef_types=["host name", "domain"],
    )
    type: str | None = Param(
        description="DNS Record Type",
        required=False,
        default=None,
        value_list=["A", "AAAA", "CNAME", "HINFO", "ISDN", "MX", "NS", "SOA", "TXT"],
    )


class RecordInfoOutput(ActionOutput):
    """One DNS record string."""

    record_info: str = OutputField(cef_types=["ip"], example_values=["122.122.122.122"])


class LookupDomainOutput(ActionOutput):
    """Forward lookup data in the aggregate shape used by the legacy action."""

    record_info_objects: list[RecordInfoOutput] = OutputField()
    record_infos: list[str] = OutputField(
        cef_types=["ip"], example_values=["122.122.122.122"]
    )


class LookupDomainSummary(ActionOutput):
    """Forward lookup summary fields."""

    total_record_infos: int | None = OutputField(example_values=[1, 6])
    record_info: str | None = OutputField(
        cef_types=["ip"], example_values=["122.122.122.122"]
    )
    canonical_name: str | None = OutputField(example_values=["phantomtest.com."])


def lookup_domain(
    params: LookupDomainParams, soar: SOARClient, asset
) -> LookupDomainOutput:
    """Query DNS records for a domain or host name."""
    domain = params.domain
    record_type = params.type or "A"
    if is_ip_address(domain):
        raise ValueError(TARGET_NOT_HOSTNAME)

    if params.type is None:
        # BaseConnector inserted the legacy default into action parameters.
        record_type = "A"

    resolver = create_resolver(asset.dns_server)
    try:
        answer = resolver.resolve(domain, record_type)
    except Exception as exc:
        message = error_message(exc)
        if any(
            phrase in message
            for phrase in (
                "None of DNS query names exist",
                "The DNS query name does not exist",
            )
        ):
            return ActionResult(True, message, params.model_dump())
        raise RuntimeError(f"{LOOKUP_QUERY_ERROR}. Error string: '{exc}'") from exc

    records = [str(item) for item in answer]
    summary = {
        "total_record_infos": len(records),
        "record_info": records[0] if records else None,
        "canonical_name": str(answer.canonical_name),
    }
    soar.set_summary(LookupDomainSummary(**summary))
    soar.set_message(
        f"Record info: {records[0] if records else None}, Total record infos: {len(records)}, "
        f"Canonical name: {answer.canonical_name}"
    )
    return LookupDomainOutput(
        record_info_objects=[
            RecordInfoOutput(record_info=record) for record in records
        ],
        record_infos=records,
    )
