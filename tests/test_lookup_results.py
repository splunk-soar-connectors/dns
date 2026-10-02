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
"""Regression tests for DNS output serialization and missing result values."""

from types import SimpleNamespace

from src.actions import lookup_domain as forward_module
from src.actions.lookup_domain import LookupDomainParams, lookup_domain
from src.actions.lookup_ip import LookupIpParams, lookup_ip


class FakeSOAR:
    def __init__(self):
        self.summary = None
        self.message = None

    def set_summary(self, summary):
        self.summary = summary

    def set_message(self, message):
        self.message = message


def test_forward_lookup_serializes_full_results_and_unmodelled_dns_fields(monkeypatch):
    class Record:
        def __init__(self, text, ttl, vendor_field):
            self.text = text
            self.ttl = ttl
            self.vendor_field = vendor_field

        def __str__(self):
            return self.text

    records = [Record("192.0.2.1", 300, "preserved-extra")]

    class Answer(list):
        canonical_name = "example.test."

    monkeypatch.setattr(
        forward_module,
        "create_resolver",
        lambda _server: SimpleNamespace(resolve=lambda *_args: Answer(records)),
    )

    soar = FakeSOAR()
    result = lookup_domain(
        LookupDomainParams(domain="example.test", type="A"),
        soar,
        SimpleNamespace(dns_server=None),
    )

    assert result.model_dump() == {
        "record_info_objects": [
            {
                "text": "192.0.2.1",
                "ttl": 300,
                "vendor_field": "preserved-extra",
                "record_info": "192.0.2.1",
            }
        ],
        "record_infos": ["192.0.2.1"],
        "domain": "example.test",
        "type": "A",
    }
    assert soar.summary.model_dump(by_alias=True) == {
        "total_record_infos": 1,
        "record_info": "192.0.2.1",
        "hostname": None,
        "cannonical_name": "example.test.",
        "canonical_name": None,
    }


def test_forward_lookup_explicitly_serializes_missing_values(monkeypatch):
    class MissingResolver:
        def resolve(self, *_args):
            raise RuntimeError("None of DNS query names exist: missing.example.")

    monkeypatch.setattr(
        forward_module, "create_resolver", lambda _server: MissingResolver()
    )
    soar = FakeSOAR()
    result = lookup_domain(
        LookupDomainParams(domain="missing.example", type=None),
        soar,
        SimpleNamespace(dns_server=None),
    )

    assert result.model_dump() == {
        "record_info_objects": [],
        "record_infos": None,
        "domain": "missing.example",
        "type": "A",
    }
    assert soar.message.startswith("Error Code: Error code unavailable.")


def test_reverse_lookup_serializes_aliases_and_null_defaults(monkeypatch):
    class Answer(list):
        canonical_name = "1.2.0.192.in-addr.arpa."

    monkeypatch.setattr(
        "src.actions.lookup_ip.create_resolver",
        lambda _server: SimpleNamespace(
            resolve=lambda *_args: Answer(["host.example."])
        ),
    )
    soar = FakeSOAR()
    result = lookup_ip(
        LookupIpParams(ip="192.0.2.1"), soar, SimpleNamespace(dns_server=None)
    )

    assert result.model_dump() == {"data": "host.example."}
    assert soar.summary.model_dump(by_alias=True) == {
        "ip": "192.0.2.1",
        "hostname": "host.example.",
        "cannonical_name": "1.2.0.192.in-addr.arpa.",
        "canonical_name": None,
    }


def test_reverse_lookup_missing_ptr_explicitly_serializes_null(monkeypatch):
    class MissingResolver:
        def resolve(self, *_args):
            raise RuntimeError(
                "The DNS query name does not exist: missing.in-addr.arpa."
            )

    monkeypatch.setattr(
        "src.actions.lookup_ip.create_resolver", lambda _server: MissingResolver()
    )
    soar = FakeSOAR()
    result = lookup_ip(
        LookupIpParams(ip="192.0.2.8"), soar, SimpleNamespace(dns_server=None)
    )

    assert result.model_dump() == {"data": None}
    assert soar.summary is None
