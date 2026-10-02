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

from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    OutputField,
    PermissiveActionOutput,
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


class RecordInfoOutput(PermissiveActionOutput):
    """One DNS record string."""

    record_info: str = OutputField(cef_types=["ip"], example_values=["122.122.122.122"])


class LookupDomainOutput(PermissiveActionOutput):
    """Forward lookup results; permissive serialization retains DNS-specific fields."""

    record_info_objects: list[RecordInfoOutput] = OutputField()
    # The legacy manifest calls this a string even though the connector emits a list.
    record_infos: str | None = OutputField(
        cef_types=["ip"], example_values=["122.122.122.122"]
    )
    domain: str | None = OutputField(cef_types=["host name", "domain"])
    type: str | None = OutputField()


class LookupDomainSummary(ActionOutput):
    """Forward lookup summary fields and their legacy aliases."""

    total_record_infos: int | None = OutputField(
        column_name="Total Record Infos", example_values=[1, 6]
    )
    record_info: str | None = OutputField(
        column_name="IP Address", cef_types=["ip"], example_values=["122.122.122.122"]
    )
    hostname: str | None = OutputField(
        column_name="Hostname",
        cef_types=["host name", "domain"],
        example_values=["ffobaaar.com"],
    )
    canonical_name: str | None = OutputField(
        alias="cannonical_name", example_values=["phantomtest.com."]
    )
    canonical_name_corrected: str | None = OutputField(alias="canonical_name")


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
        if "None of DNS query names exist" in message:
            soar.set_message(message)
            return LookupDomainOutput(
                record_info_objects=[],
                record_infos=None,
                domain=domain,
                type=record_type,
            )
        raise RuntimeError(f"{LOOKUP_QUERY_ERROR}. Error string: '{exc}'") from exc

    records = [str(item) for item in answer]
    raw_data: dict[str, Any] = {
        "record_info_objects": [
            _record_payload(item, record)
            for item, record in zip(records, answer, strict=True)
        ],
        "record_infos": records,
        "domain": domain,
        "type": record_type,
    }
    result = LookupDomainOutput(**raw_data)
    summary = {
        "total_record_infos": len(records),
        "record_info": records[0] if records else None,
        "hostname": None,
        "cannonical_name": str(answer.canonical_name),
        "canonical_name": None,
    }
    soar.set_summary(LookupDomainSummary(**summary))
    soar.set_message(
        f"Record info: {records[0] if records else None}, Total record infos: {len(records)}, "
        f"Cannonical name: {answer.canonical_name}"
    )
    return result


def _record_payload(record_info: str, record: Any) -> dict[str, Any]:
    """Keep public fields exposed by a DNS record in permissive result serialization."""
    raw_fields = getattr(record, "__dict__", {})
    return {
        **{key: value for key, value in raw_fields.items() if not key.startswith("_")},
        "record_info": record_info,
    }


def display_domain_results(outputs: list[LookupDomainOutput]) -> dict:
    """Prepare DNS lookup results for the legacy custom view template."""
    return {"results": [output.model_dump() for output in outputs]}
