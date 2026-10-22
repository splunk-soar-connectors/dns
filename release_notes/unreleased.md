**Unreleased**

* Convert DNS from BaseConnector to the Splunk SOAR SDK.
* Correct the misspelled `cannonical_name` summary output key to `canonical_name` for the lookup domain and lookup IP actions.
* **Breaking change:** The `lookup ip` action now returns structured hostname objects instead of hostname strings in `action_result.data` (for example, `[{"hostname": "dns.google."}]` instead of `["dns.google."]`). Update playbooks and other consumers that read hostname values directly from `action_result.data` to use `action_result.data.*.hostname`. The `action_result.summary.hostname` output is unchanged.
