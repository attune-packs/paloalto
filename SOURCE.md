# Source and API Verification

## Attributed Source

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-paloalto
- Upstream pack version: `1.0.0`
- Verified revision: `efdc0db1dc96f94c4288a9c2ff227f2c9d0ee05e`
- Revision date: `2021-12-19T07:26:47Z`
- Revision signature: present but not verified by GitHub (`unknown_key`)
- Latest upstream tag: `v1.0.0` at `3cab9cc65907e8feab929b4168964a0b99b98a06`
- Revision relation: four commits after `v1.0.0` (`v1.0.0-4-gefdc0db`)
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision

The upstream pack declares the unpinned `pandevice` package and relies on its
runtime class discovery, object serialization, and commit behavior. This
adaptation uses none of that code directly. It retains the useful object,
dynamic-registration, and commit intent while replacing credentials,
placement, API calls, contracts, parsing, polling, and error handling.

## Current API and Client Baseline

- Review date: `2026-08-14`
- Current Palo Alto-maintained client reviewed: `pan-os-python` `v1.13.1`
- Client revision reviewed: `92ed648d89b7541052a15e234eb34e99edba6d2d`
- Current client release date: `2026-07-22`
- PAN-OS XML API documentation update shown by Palo Alto Networks: `2025-08-28`
- Dynamic registration administration documentation update: `2025-08-11`

Authoritative references:

- https://docs.paloaltonetworks.com/ngfw/api/getting-started/explore-xmlapi
- https://docs.paloaltonetworks.com/ngfw/api/getting-started/xpath-node-selection
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit-all
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/asynchronous-and-synchronous-requests-to-the-pan-os-xml-api
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/run-operational-mode-commands-api
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/register-ip-addresses-and-tags-dynamically
- https://github.com/PaloAltoNetworks/pan-os-python/tree/v1.13.1

Verified behavior used by this pack:

- Current guidance supports `type=keygen` bootstrap and `X-PAN-KEY` request
  authentication.
- Config `get` reads candidate configuration; `set`, `edit`, and `delete`
  mutate candidate configuration. `edit` replaces the selected hierarchy.
- Firewall objects and local security policy are under a vsys. Panorama policy
  objects are shared or device-group scoped; policy rules use pre/post
  rulebases. Templates are a different device/network configuration domain.
- Commit and commit-all enqueue asynchronous jobs that are inspected with the
  fixed `show jobs id` operational command.
- Commit-all shared-policy XML uses a named device-group, optional device
  serial entries, and `include-template=no` when template changes must not be
  pushed. Parent device-group pushes do not recurse to child-group devices.
- User-ID dynamic registration uses `uid-message` register/unregister payloads,
  supports firewall and Panorama, and permits mapping timeouts up to 2,592,000
  seconds. IPv4 sets may be subnets or ranges; network/range sets are IPv4.
- The documented pending-change summary command is `show config list
  change-summary`.

The PAN-OS REST API was not selected for this pack. The curated surface spans
configuration, User-ID, operational, and commit request types already covered
by the XML API, while REST resource availability and versions vary by PAN-OS
release. No generic client behavior or old `pandevice` default was carried
forward without a constrained XML contract.
