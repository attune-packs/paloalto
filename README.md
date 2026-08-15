# Palo Alto Networks PAN-OS Attune Pack

This pack adapts the Apache-2.0 StackStorm Exchange Palo Alto pack at revision
`efdc0db1dc96f94c4288a9c2ff227f2c9d0ee05e`. It replaces the old unpinned
`pandevice` dependency and StackStorm configuration model with 27 curated
Attune actions over one constrained PAN-OS XML API client.

The implementation was reviewed against Palo Alto Networks' current XML API
documentation and the Palo Alto-maintained `pan-os-python` v1.13.1 client. See
[SOURCE.md](SOURCE.md) for the verified source and API baseline.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- HTTPS reachability from the worker to a firewall or Panorama management API.
- A pack-owned encrypted Attune Key, normally `paloalto.credentials`.
- A least-privilege PAN-OS XML API administrator role for the selected actions.
- A trusted appliance certificate or the issuing CA certificate in the Key.

No third-party Python dependency is required. Live behavior depends on the
target's PAN-OS release, licenses, administrator role, and configuration model.

## Credentials

Every action requests Attune's `standard` execution permission and receives
only an Attune Key reference. The Key value must be a flat JSON object.

Preferred API-key credential:

```json
{
  "base_url": "https://firewall.example.com",
  "target_type": "firewall",
  "api_key": "REDACTED_PAN_OS_API_KEY",
  "verify_tls": true
}
```

Username/password bootstrap for a Panorama with a private CA:

```json
{
  "base_url": "https://panorama.example.com:443",
  "target_type": "panorama",
  "username": "attune-api",
  "password": "REDACTED_PASSWORD",
  "verify_tls": true,
  "ca_cert": "-----BEGIN CERTIFICATE-----\nREDACTED_CA_PEM\n-----END CERTIFICATE-----"
}
```

Use exactly one authentication mode. Bootstrap calls `type=keygen`; the
generated key remains in process memory for that action and is never returned,
printed, or persisted. API keys are sent in `X-PAN-KEY`, not URLs or form data.
The client accepts only an HTTPS origin without URL credentials or a path,
rejects redirects, and requires TLS verification. `verify_tls` therefore must
be `true`; use `ca_cert` for private trust roots instead of disabling checks.

All timeouts are bounded to 1 through 300 seconds. Responses are capped at 8
MiB. HTTP, API, SDK, and parser errors do not include response bodies, request
forms, keys, passwords, or library exception text.

## Targeting and Placement

The action `target_type` is mandatory and must equal the credential Key's
`target_type`. This prevents accidentally treating Panorama as a firewall.

| Target | Object scope | Security policy position | XPath placement |
|---|---|---|---|
| Firewall | `local` | `local` | selected `vsys` (default in code: `vsys1`) and local `rulebase` |
| Panorama | `shared` | `pre` or `post` | `/config/shared` and shared pre/post rulebase |
| Panorama | `device_group` | `pre` or `post` | named device group and its pre/post rulebase |

Object and policy actions never write templates or template stacks. Those
areas hold device/network settings, not shared/device-group policy objects.
Panorama `commit_all` always emits `include-template=no` and pushes only shared
policy for the named device group. Per current Panorama API behavior, a push to
a parent device group does not automatically include devices attached only to
child device groups; invoke each intended device group explicitly.

Dynamic address registration with a `firewall` credential targets that
firewall. With a `panorama` credential, omitting `managed_device_serial`
registers on Panorama; supplying a validated serial uses the XML API `target`
parameter for that managed firewall. This destination is always included in
action metadata.

## Actions

| Actions | Purpose |
|---|---|
| `address_object_{get,create,update,delete}` | Candidate-config IP/netmask, range, FQDN, or wildcard address object CRUD |
| `address_group_{get,create,update,delete}` | Candidate-config static or dynamic address group CRUD |
| `service_object_{get,create,update,delete}` | Candidate-config TCP/UDP service object CRUD with validated ports |
| `service_group_{get,create,update,delete}` | Candidate-config service group CRUD |
| `security_rule_{get,create,update,delete}` | Constrained candidate-config security rule CRUD |
| `dynamic_address_register` | Register tags for IP hosts, IPv4 networks/ranges, and an optional bounded timeout |
| `dynamic_address_unregister` | Unregister only supplied address/tag pairs after confirmation |
| `pending_changes` | Fixed `show config list change-summary` operational command |
| `system_info` | Fixed `show system info` operational command |
| `job_status` | Fixed `show jobs id` command for a numeric job ID |
| `commit` | Commit firewall or Panorama-local candidate config, optionally polling |
| `commit_all` | Push one Panorama device group's shared policy, optionally limited to serials |

There is deliberately no arbitrary XPath, XML, operational-command, REST, or
raw API action. Webhook-trigger rules are deferred because exposing a secure,
authenticated, replay-resistant Attune ingress endpoint is a separate design.

## Mutation Semantics

Configuration creates first read candidate configuration and fail if the name
already exists. Updates and deletes fail if it does not exist. The existence
check and mutation are separate XML API requests, so concurrent writers still
need external coordination. A mutation is sent once and is never retried after
an ambiguous timeout or connection failure.

Updates use PAN-OS `action=edit`, which replaces the selected hierarchy. They
require `confirm_name` to exactly equal `name`. Security-rule updates also
inspect the existing rule and reject it if fields outside this pack's supported
contract would be lost. Deletes require the same exact-name confirmation.
Unregister requires `confirm: UNREGISTER`; commit and commit-all require
`COMMIT` and `COMMIT-ALL` respectively.

The security-rule contract covers zones, sources, destinations, source users,
applications, services, URL categories, action, description, tags, enabled
state, log start/end, log forwarding profile, security profile group, and
schedule. Rule order/move, target negation, individual security profiles,
decryption/NAT/QoS policy, and version-specific advanced options are omitted.
`security_rule_get` reports unsupported top-level fields so callers can detect
rules that this pack will not replace.

All object and rule changes remain candidate changes. The pack never commits
implicitly. On Panorama, `commit` commits Panorama-local candidate changes;
`commit_all` is a separate subsequent deployment operation and does not perform
the local commit first.

Commit requests return the queued job ID. With `wait: true`, polling is bounded
by `max_polls` (1 to 120) and `poll_interval_seconds` (1 to 30); only status
requests are repeated. With `wait: false`, use `job_status`. A successful
response with no job is returned as `NO_CHANGES`.

## Output Contract

Every action accepts one flat JSON object and returns:

```json
{
  "operation": "address_object_create",
  "target_type": "panorama",
  "changed": true,
  "data": {
    "name": "web-prod",
    "candidate_config": true
  },
  "meta": {
    "api": "PAN-OS XML API",
    "scope": "device_group",
    "vsys": null,
    "device_group": "production"
  }
}
```

`changed` is `null` for reads, `false` for a no-change commit, and otherwise a
boolean. Raw response XML, API keys, and passwords are never output.

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q /home/david/Codebase/attune-packs/paloalto
attune --output json pack check /home/david/Codebase/attune-packs/paloalto
attune pack test /home/david/Codebase/attune-packs/paloalto --detailed
```

Tests mock the appliance and Attune Key API deterministically. A live test is a
deployment responsibility because PAN-OS versions, Panorama hierarchy, API
roles, certificates, and commit impact differ by environment.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).
