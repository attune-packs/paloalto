"""Constrained PAN-OS/Panorama XML API client and action dispatcher."""

from __future__ import annotations

import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

DEFAULT_CREDENTIAL_KEY = "pack.paloalto.credentials"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 1000
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,62}$")
_SERIAL = re.compile(r"^[A-Za-z0-9]{6,32}$")
_JOB_ID = re.compile(r"^[0-9]{1,20}$")
_OBJECT_KINDS = {
    "address_object": "address",
    "address_group": "address-group",
    "service_object": "service",
    "service_group": "service-group",
}
_READ_OPERATIONS = {"pending_changes", "job_status", "system_info"}


class PanosPackError(Exception):
    """An action-safe exception that never includes credentials or response XML."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise PanosPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(key_ref, client=attune.context.client)
    except Exception as exc:  # noqa: BLE001
        raise PanosPackError(f"could not read Palo Alto credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise PanosPackError("Palo Alto credential Key was not found")
        raise PanosPackError(f"could not read Palo Alto credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise PanosPackError("Palo Alto credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise PanosPackError("Palo Alto credential Key must contain an object")
    return value


def _string(value: Any, name: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise PanosPackError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 32 for character in value):
        raise PanosPackError(f"{name} contains a control character")
    return value


def _optional_string(params: dict[str, Any], name: str, *, maximum: int = 1024) -> str | None:
    value = params.get(name)
    return None if value is None else _string(value, name, maximum=maximum)


def _name(value: Any, label: str) -> str:
    value = _string(value, label, maximum=63)
    if not _SAFE_NAME.fullmatch(value):
        raise PanosPackError(f"{label} contains characters that are unsafe for PAN-OS XPath")
    return value


def _serial(value: Any, label: str = "managed_device_serial") -> str:
    value = _string(value, label, maximum=32)
    if not _SERIAL.fullmatch(value):
        raise PanosPackError(f"{label} is not a valid device serial")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise PanosPackError(f"{name} must be a boolean")
    return value


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PanosPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _string_list(
    value: Any,
    name: str,
    *,
    required: bool = False,
    names: bool = True,
    maximum: int = MAX_ITEMS,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise PanosPackError(f"{name} must be an array with at most {maximum} items")
    if required and not value:
        raise PanosPackError(f"{name} must not be empty")
    result = [(_name(item, f"{name} item") if names else _string(item, f"{name} item", maximum=255)) for item in value]
    if len(set(result)) != len(result):
        raise PanosPackError(f"{name} must not contain duplicates")
    return result


def _registered_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if "-" in value:
        start_text, separator, end_text = value.partition("-")
        if separator and start_text and end_text:
            try:
                start = ipaddress.ip_address(start_text)
                end = ipaddress.ip_address(end_text)
            except ValueError:
                pass
            else:
                if start.version == 4 and end.version == 4 and int(start) <= int(end):
                    return f"{start}-{end}"
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise PanosPackError("ip_addresses must contain IP hosts, IPv4 networks, or ascending IPv4 ranges") from None
    if network.version != 4:
        raise PanosPackError("dynamic address group networks and ranges must use IPv4")
    return str(network)


def _choice(params: dict[str, Any], name: str, allowed: set[str], default: str | None = None) -> str:
    value = params.get(name, default)
    if value not in allowed:
        raise PanosPackError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return value


def _parse_xml(body: bytes) -> ET.Element:
    if len(body) > MAX_RESPONSE_BYTES:
        raise PanosPackError("PAN-OS response exceeded the 8 MiB action limit")
    lowered = body.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise PanosPackError("PAN-OS returned prohibited DTD or entity XML")
    try:
        return ET.fromstring(body)
    except ET.ParseError:
        raise PanosPackError("PAN-OS returned invalid XML") from None


def _xml_text(element: ET.Element | None, path: str, default: str | None = None) -> str | None:
    found = element.find(path) if element is not None else None
    return found.text.strip() if found is not None and found.text else default


def _xml_data(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        return (element.text or "").strip()
    result: dict[str, Any] = {}
    for child in children:
        value = _xml_data(child)
        if child.attrib:
            value = {"attributes": dict(child.attrib), "value": value}
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


def _members(parent: ET.Element, tag: str, values: list[str]) -> None:
    container = ET.SubElement(parent, tag)
    for value in values:
        ET.SubElement(container, "member").text = value


def _yes_no(parent: ET.Element, tag: str, value: bool) -> None:
    ET.SubElement(parent, tag).text = "yes" if value else "no"


def _element_xml(element: ET.Element) -> str:
    return ET.tostring(element, encoding="unicode", short_empty_elements=True)


class PanosClient:
    """Small no-retry XML API client with an in-memory API key."""

    def __init__(self, credential: dict[str, Any], target_type: str, timeout_seconds: int):
        base_url = credential.get("base_url")
        if not isinstance(base_url, str):
            raise PanosPackError("credential base_url must be a string")
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise PanosPackError("credential base_url must be an HTTPS origin without credentials, path, query, or fragment")
        try:
            _ = parsed.port
        except ValueError:
            raise PanosPackError("credential base_url has an invalid port") from None
        credential_target = credential.get("target_type")
        if credential_target not in {"firewall", "panorama"}:
            raise PanosPackError("credential target_type must be 'firewall' or 'panorama'")
        if credential_target != target_type:
            raise PanosPackError("action target_type does not match the credential Key target_type")
        verify_tls = credential.get("verify_tls", True)
        if verify_tls is not True:
            raise PanosPackError("TLS verification must remain enabled for PAN-OS credentials")
        ca_cert = credential.get("ca_cert")
        if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip()):
            raise PanosPackError("credential ca_cert must be a non-empty PEM string")
        context = ssl.create_default_context()
        if ca_cert:
            try:
                context.load_verify_locations(cadata=ca_cert)
            except ssl.SSLError:
                raise PanosPackError("credential ca_cert is not valid CA PEM") from None
        api_key = credential.get("api_key")
        username = credential.get("username")
        password = credential.get("password")
        using_key = api_key is not None
        using_password = username is not None or password is not None
        if using_key == using_password:
            raise PanosPackError("credential must contain either api_key or username/password, but not both")
        if using_key:
            self.api_key = _string(api_key, "credential api_key", maximum=4096)
        else:
            username = _string(username, "credential username", maximum=128)
            password = _string(password, "credential password", maximum=4096)
            self.api_key = ""
        self.base_url = base_url.rstrip("/") + "/api/"
        self.timeout_seconds = timeout_seconds
        self.context = context
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )
        if not using_key:
            self.api_key = self._bootstrap_key(username, password)

    def _post(self, params: dict[str, str], *, authenticated: bool = True) -> ET.Element:
        headers = {"Accept": "application/xml", "Content-Type": "application/x-www-form-urlencoded"}
        if authenticated:
            headers["X-PAN-KEY"] = self.api_key
        request = urllib.request.Request(
            self.base_url,
            data=urllib.parse.urlencode(params).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            raise PanosPackError(f"PAN-OS returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PanosPackError(f"PAN-OS request failed ({type(exc).__name__})") from None
        if not 200 <= status < 300:
            raise PanosPackError(f"PAN-OS returned HTTP {status}")
        root = _parse_xml(body)
        if root.tag != "response":
            raise PanosPackError("PAN-OS returned an unexpected XML document")
        if root.get("status") != "success":
            code = root.get("code")
            suffix = f" code {code}" if code and code.isdigit() else ""
            raise PanosPackError(f"PAN-OS API returned an error{suffix}")
        return root

    def _bootstrap_key(self, username: str, password: str) -> str:
        root = self._post({"type": "keygen", "user": username, "password": password}, authenticated=False)
        key = _xml_text(root, "./result/key")
        if not key:
            raise PanosPackError("PAN-OS key bootstrap response did not contain a key")
        return key

    def request(self, request_type: str, **params: str) -> ET.Element:
        return self._post({"type": request_type, **params})

    def config(self, action: str, xpath: str, element: ET.Element | None = None) -> ET.Element:
        params = {"action": action, "xpath": xpath}
        if element is not None:
            params["element"] = _element_xml(element)
        return self.request("config", **params)

    def op(self, command: ET.Element) -> ET.Element:
        return self.request("op", cmd=_element_xml(command))


def _target_type(params: dict[str, Any]) -> str:
    return _choice(params, "target_type", {"firewall", "panorama"})


def _scope_root(params: dict[str, Any], target_type: str) -> tuple[str, dict[str, str | None]]:
    scope = _choice(params, "scope", {"local", "shared", "device_group"})
    device_group = params.get("device_group")
    vsys = params.get("vsys")
    if target_type == "firewall":
        if scope != "local" or device_group is not None:
            raise PanosPackError("firewall configuration requires local scope and does not accept device_group")
        vsys_name = _name(vsys or "vsys1", "vsys")
        return (
            f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys_name}']",
            {"scope": "local", "vsys": vsys_name, "device_group": None},
        )
    if vsys is not None:
        raise PanosPackError("Panorama shared/device_group configuration does not accept vsys")
    if scope == "shared":
        if device_group is not None:
            raise PanosPackError("shared Panorama scope does not accept device_group")
        return "/config/shared", {"scope": "shared", "vsys": None, "device_group": None}
    if scope == "device_group":
        group = _name(device_group, "device_group")
        return (
            f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{group}']",
            {"scope": "device_group", "vsys": None, "device_group": group},
        )
    raise PanosPackError("Panorama configuration requires shared or device_group scope")


def _object_xpath(params: dict[str, Any], target_type: str, kind: str) -> tuple[str, str, dict[str, str | None]]:
    root, location = _scope_root(params, target_type)
    name = _name(params.get("name"), "name")
    collection = _OBJECT_KINDS[kind]
    return f"{root}/{collection}", name, location


def _result_entry(root: ET.Element, *, required: bool, expected_name: str) -> ET.Element | None:
    result = root.find("./result")
    entry = result.find(".//entry") if result is not None else None
    if required and entry is None:
        raise PanosPackError("PAN-OS object was not found")
    if entry is not None and entry.get("name") != expected_name:
        raise PanosPackError("PAN-OS returned an unexpected object")
    return entry


def _member_values(entry: ET.Element, path: str) -> list[str]:
    return [(item.text or "") for item in entry.findall(path) if item.text is not None]


def _normalize_object(kind: str, entry: ET.Element) -> dict[str, Any]:
    data: dict[str, Any] = {"name": entry.get("name")}
    description = _xml_text(entry, "description")
    tags = _member_values(entry, "tag/member")
    if kind == "address_object":
        value_node = next((entry.find(tag) for tag in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard-mask") if entry.find(tag) is not None), None)
        if value_node is None:
            raise PanosPackError("PAN-OS returned an unexpected address object")
        data.update({"address_type": value_node.tag, "value": value_node.text or ""})
    elif kind == "address_group":
        static = entry.find("static")
        dynamic = entry.find("dynamic")
        if static is not None:
            data.update({"group_type": "static", "members": _member_values(entry, "static/member"), "filter": None})
        elif dynamic is not None:
            data.update({"group_type": "dynamic", "members": [], "filter": _xml_text(entry, "dynamic/filter")})
        else:
            raise PanosPackError("PAN-OS returned an unexpected address group")
    elif kind == "service_object":
        if entry.find("protocol/tcp") is not None:
            protocol = "tcp"
        elif entry.find("protocol/udp") is not None:
            protocol = "udp"
        else:
            raise PanosPackError("PAN-OS returned an unexpected service object")
        data.update({
            "protocol": protocol,
            "destination_port": _xml_text(entry, f"protocol/{protocol}/port"),
            "source_port": _xml_text(entry, f"protocol/{protocol}/source-port"),
        })
    elif kind == "service_group":
        data["members"] = _member_values(entry, "members/member")
    data["description"] = description
    data["tags"] = tags
    return data


def _build_object(kind: str, params: dict[str, Any], name: str) -> ET.Element:
    entry = ET.Element("entry", {"name": name})
    description = _optional_string(params, "description", maximum=1023)
    if kind != "service_group" and description is not None:
        ET.SubElement(entry, "description").text = description
    if kind == "address_object":
        address_type = _choice(params, "address_type", {"fqdn", "ip-netmask", "ip-range", "ip-wildcard-mask"})
        value = _string(params.get("value"), "value", maximum=255)
        _validate_address_value(address_type, value)
        ET.SubElement(entry, address_type).text = value
    elif kind == "address_group":
        group_type = _choice(params, "group_type", {"static", "dynamic"})
        members = _string_list(params.get("members", []), "members")
        filter_value = _optional_string(params, "filter", maximum=2047)
        if group_type == "static":
            if filter_value is not None:
                raise PanosPackError("static address groups do not accept filter")
            _members(entry, "static", members)
        else:
            if members:
                raise PanosPackError("dynamic address groups do not accept members")
            dynamic = ET.SubElement(entry, "dynamic")
            ET.SubElement(dynamic, "filter").text = _string(filter_value, "filter", maximum=2047)
    elif kind == "service_object":
        protocol = _choice(params, "protocol", {"tcp", "udp"})
        destination = _string(params.get("destination_port"), "destination_port", maximum=255)
        source = _optional_string(params, "source_port", maximum=255)
        _validate_ports(destination, "destination_port")
        if source is not None:
            _validate_ports(source, "source_port")
        protocol_node = ET.SubElement(ET.SubElement(entry, "protocol"), protocol)
        ET.SubElement(protocol_node, "port").text = destination
        if source is not None:
            ET.SubElement(protocol_node, "source-port").text = source
    elif kind == "service_group":
        _members(entry, "members", _string_list(params.get("members"), "members", required=True))
    tags = _string_list(params.get("tags", []), "tags")
    if tags:
        _members(entry, "tag", tags)
    return entry


def _validate_address_value(address_type: str, value: str) -> None:
    try:
        if address_type == "ip-netmask":
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
        elif address_type == "ip-range":
            start_text, separator, end_text = value.partition("-")
            if not separator:
                raise ValueError
            start, end = ipaddress.ip_address(start_text), ipaddress.ip_address(end_text)
            if start.version != end.version or int(start) > int(end):
                raise ValueError
        elif address_type == "ip-wildcard-mask":
            address, separator, mask = value.partition("/")
            if not separator:
                raise ValueError
            if ipaddress.ip_address(address).version != 4 or ipaddress.ip_address(mask).version != 4:
                raise ValueError
        else:
            if len(value) > 253 or value.startswith(".") or value.endswith("."):
                raise ValueError
            labels = value.split(".")
            if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
                raise ValueError
    except ValueError:
        raise PanosPackError(f"value is not valid for address_type {address_type}") from None


def _validate_ports(value: str, name: str) -> None:
    for item in value.split(","):
        if not item or item.strip() != item:
            raise PanosPackError(f"{name} must be comma-separated ports or ascending port ranges")
        start_text, separator, end_text = item.partition("-")
        values = (start_text, end_text) if separator else (start_text,)
        if any(not part.isdigit() or not 1 <= int(part) <= 65535 for part in values):
            raise PanosPackError(f"{name} must contain ports from 1 to 65535")
        if separator and int(start_text) > int(end_text):
            raise PanosPackError(f"{name} ranges must be ascending")


def _object_action(client: PanosClient, operation: str, params: dict[str, Any], target_type: str) -> tuple[Any, bool | None, dict[str, Any]]:
    kind, verb = operation.rsplit("_", 1)
    parent, name, location = _object_xpath(params, target_type, kind)
    entry_xpath = f"{parent}/entry[@name='{name}']"
    if verb == "get":
        entry = _result_entry(client.config("get", entry_xpath), required=True, expected_name=name)
        return _normalize_object(kind, entry), None, location
    if verb in {"update", "delete"} and params.get("confirm_name") != name:
        purpose = "replacement update" if verb == "update" else "delete"
        raise PanosPackError(f"confirm_name must exactly match name for {purpose}")
    current = _result_entry(client.config("get", entry_xpath), required=False, expected_name=name)
    if verb == "create":
        if current is not None:
            raise PanosPackError("PAN-OS object already exists")
        client.config("set", parent, _build_object(kind, params, name))
        return {"name": name, "candidate_config": True}, True, location
    if verb == "update":
        if current is None:
            raise PanosPackError("PAN-OS object was not found")
        client.config("edit", entry_xpath, _build_object(kind, params, name))
        return {"name": name, "candidate_config": True}, True, location
    if verb == "delete":
        if current is None:
            raise PanosPackError("PAN-OS object was not found")
        client.config("delete", entry_xpath)
        return {"name": name, "candidate_config": True}, True, location
    raise PanosPackError("unsupported object action")


def _security_xpath(params: dict[str, Any], target_type: str) -> tuple[str, str, dict[str, Any]]:
    root, location = _scope_root(params, target_type)
    position = _choice(params, "policy_position", {"local", "pre", "post"})
    if target_type == "firewall":
        if position != "local":
            raise PanosPackError("firewall security policy requires local policy_position")
        rulebase = "rulebase"
    else:
        if position == "local":
            raise PanosPackError("Panorama security policy requires pre or post policy_position")
        rulebase = f"{position}-rulebase"
    name = _name(params.get("name"), "name")
    location["policy_position"] = position
    return f"{root}/{rulebase}/security/rules", name, location


def _build_security_rule(params: dict[str, Any], name: str) -> ET.Element:
    entry = ET.Element("entry", {"name": name})
    list_fields = (
        ("from_zones", "from"),
        ("to_zones", "to"),
        ("sources", "source"),
        ("destinations", "destination"),
        ("source_users", "source-user"),
        ("applications", "application"),
        ("services", "service"),
        ("categories", "category"),
    )
    for parameter, xml_name in list_fields:
        default = ["any"] if parameter in {"source_users", "categories"} else None
        value = params.get(parameter, default)
        names = parameter != "source_users"
        _members(entry, xml_name, _string_list(value, parameter, required=True, names=names))
    action = _choice(params, "action", {"allow", "deny", "drop", "reset-both", "reset-client", "reset-server"})
    ET.SubElement(entry, "action").text = action
    description = _optional_string(params, "description", maximum=1023)
    if description is not None:
        ET.SubElement(entry, "description").text = description
    tags = _string_list(params.get("tags", []), "tags")
    if tags:
        _members(entry, "tag", tags)
    _yes_no(entry, "disabled", _boolean(params, "disabled"))
    _yes_no(entry, "log-start", _boolean(params, "log_start"))
    _yes_no(entry, "log-end", _boolean(params, "log_end", True))
    for parameter, xml_name in (("log_setting", "log-setting"), ("schedule", "schedule")):
        value = _optional_string(params, parameter, maximum=63)
        if value is not None:
            ET.SubElement(entry, xml_name).text = _name(value, parameter)
    profile_group = _optional_string(params, "profile_group", maximum=63)
    if profile_group is not None:
        setting = ET.SubElement(entry, "profile-setting")
        _members(setting, "group", [_name(profile_group, "profile_group")])
    return entry


def _normalize_security_rule(entry: ET.Element) -> dict[str, Any]:
    fields = {
        "from_zones": "from/member",
        "to_zones": "to/member",
        "sources": "source/member",
        "destinations": "destination/member",
        "source_users": "source-user/member",
        "applications": "application/member",
        "services": "service/member",
        "categories": "category/member",
        "tags": "tag/member",
    }
    result: dict[str, Any] = {"name": entry.get("name")}
    result.update({name: _member_values(entry, path) for name, path in fields.items()})
    result.update({
        "action": _xml_text(entry, "action"),
        "description": _xml_text(entry, "description"),
        "disabled": _xml_text(entry, "disabled", "no") == "yes",
        "log_start": _xml_text(entry, "log-start", "no") == "yes",
        "log_end": _xml_text(entry, "log-end", "no") == "yes",
        "log_setting": _xml_text(entry, "log-setting"),
        "schedule": _xml_text(entry, "schedule"),
        "profile_group": _xml_text(entry, "profile-setting/group/member"),
        "unsupported_fields": _unsupported_security_fields(entry),
    })
    return result


def _unsupported_security_fields(entry: ET.Element) -> list[str]:
    supported = {
        "from", "to", "source", "destination", "source-user", "application",
        "service", "category", "action", "description", "tag", "disabled",
        "log-start", "log-end", "log-setting", "schedule", "profile-setting",
    }
    unsupported = {child.tag for child in entry if child.tag not in supported}
    for field in ("from", "to", "source", "destination", "source-user", "application", "service", "category", "tag"):
        node = entry.find(field)
        if node is not None and any(child.tag != "member" or child.attrib for child in node):
            unsupported.add(field)
    profile = entry.find("profile-setting")
    if profile is not None:
        if any(child.tag != "group" for child in profile):
            unsupported.add("profile-setting")
        group = profile.find("group")
        if group is None or len(group) != 1 or any(child.tag != "member" or child.attrib for child in group):
            unsupported.add("profile-setting")
    for field in supported - {"from", "to", "source", "destination", "source-user", "application", "service", "category", "tag", "profile-setting"}:
        node = entry.find(field)
        if node is not None and (node.attrib or list(node)):
            unsupported.add(field)
    return sorted(unsupported)


def _security_action(client: PanosClient, operation: str, params: dict[str, Any], target_type: str) -> tuple[Any, bool | None, dict[str, Any]]:
    verb = operation.rsplit("_", 1)[1]
    parent, name, location = _security_xpath(params, target_type)
    xpath = f"{parent}/entry[@name='{name}']"
    if verb == "get":
        entry = _result_entry(client.config("get", xpath), required=True, expected_name=name)
        return _normalize_security_rule(entry), None, location
    if verb in {"update", "delete"} and params.get("confirm_name") != name:
        purpose = "replacement update" if verb == "update" else "delete"
        raise PanosPackError(f"confirm_name must exactly match name for {purpose}")
    current = _result_entry(client.config("get", xpath), required=False, expected_name=name)
    if verb == "create":
        if current is not None:
            raise PanosPackError("security rule already exists")
        client.config("set", parent, _build_security_rule(params, name))
    elif verb == "update":
        if current is None:
            raise PanosPackError("security rule was not found")
        unsupported = _unsupported_security_fields(current)
        if unsupported:
            raise PanosPackError("security rule contains fields outside the safely representable update contract")
        client.config("edit", xpath, _build_security_rule(params, name))
    elif verb == "delete":
        if current is None:
            raise PanosPackError("security rule was not found")
        client.config("delete", xpath)
    else:
        raise PanosPackError("unsupported security rule action")
    return {"name": name, "candidate_config": True}, True, location


def _dynamic_address(client: PanosClient, operation: str, params: dict[str, Any], target_type: str) -> tuple[Any, bool, dict[str, Any]]:
    addresses = _string_list(params.get("ip_addresses"), "ip_addresses", required=True, names=False)
    normalized = [_registered_ip(address) for address in addresses]
    if len(set(normalized)) != len(normalized):
        raise PanosPackError("ip_addresses must not contain duplicates")
    tags = _string_list(params.get("tags"), "tags", required=True, maximum=32)
    unregister = operation == "dynamic_address_unregister"
    if unregister and params.get("confirm") != "UNREGISTER":
        raise PanosPackError("confirm must be exactly 'UNREGISTER'")
    message = ET.Element("uid-message")
    ET.SubElement(message, "version").text = "1.0"
    ET.SubElement(message, "type").text = "update"
    payload = ET.SubElement(message, "payload")
    action = ET.SubElement(payload, "unregister" if unregister else "register")
    for address in normalized:
        entry = ET.SubElement(action, "entry", {"ip": address})
        _members(entry, "tag", tags)
        if not unregister and "registration_timeout_seconds" in params:
            timeout = _integer(params, "registration_timeout_seconds", 0, 1, 2592000)
            for member in entry.findall("tag/member"):
                member.set("timeout", str(timeout))
    request_params = {"cmd": _element_xml(message)}
    serial = params.get("managed_device_serial")
    if target_type == "panorama":
        if serial is not None:
            request_params["target"] = _serial(serial)
    elif serial is not None:
        raise PanosPackError("managed_device_serial is only valid for Panorama")
    client.request("user-id", **request_params)
    return {
        "registered": not unregister,
        "ip_addresses": normalized,
        "tags": tags,
    }, True, {"managed_device_serial": request_params.get("target")}


def _job_command(job_id: str) -> ET.Element:
    show = ET.Element("show")
    jobs = ET.SubElement(show, "jobs")
    ET.SubElement(jobs, "id").text = job_id
    return show


def _job_data(root: ET.Element, expected_id: str) -> dict[str, Any]:
    job = root.find("./result/job")
    if job is None:
        job = root.find(".//job")
    if job is None:
        raise PanosPackError("PAN-OS job status response did not contain a job")
    job_id = _xml_text(job, "id") or expected_id
    if job_id != expected_id:
        raise PanosPackError("PAN-OS job status response contained an unexpected job ID")
    progress_text = _xml_text(job, "progress")
    progress = int(progress_text) if progress_text and progress_text.isdigit() else None
    return {
        "job_id": job_id,
        "status": _xml_text(job, "status"),
        "result": _xml_text(job, "result"),
        "progress": progress,
        "details": [_xml_data(item) for item in job.findall("details/line")],
        "warnings": [_xml_data(item) for item in job.findall("warnings/line")],
    }


def _poll_job(client: PanosClient, job_id: str, params: dict[str, Any]) -> dict[str, Any]:
    interval = _integer(params, "poll_interval_seconds", 2, 1, 30)
    maximum = _integer(params, "max_polls", 60, 1, 120)
    for attempt in range(1, maximum + 1):
        data = _job_data(client.op(_job_command(job_id)), job_id)
        data["polls"] = attempt
        if data["status"] == "FIN":
            if data["result"] not in {"OK", "WARN"}:
                raise PanosPackError(f"PAN-OS job {job_id} finished with result {data['result'] or 'unknown'}")
            return data
        if attempt < maximum:
            time.sleep(interval)
    raise PanosPackError(f"PAN-OS job {job_id} did not finish within {maximum} polls")


def _initial_job(root: ET.Element) -> str | None:
    job_id = _xml_text(root, "./result/job") or _xml_text(root, ".//job/id")
    if job_id in {None, "", "0"}:
        return None
    if not _JOB_ID.fullmatch(job_id):
        raise PanosPackError("PAN-OS returned an invalid job ID")
    return job_id


def _commit(client: PanosClient, operation: str, params: dict[str, Any], target_type: str) -> tuple[Any, bool, dict[str, Any]]:
    wait = _boolean(params, "wait", True)
    comment = _optional_string(params, "comment", maximum=512)
    if operation == "commit":
        if params.get("confirm") != "COMMIT":
            raise PanosPackError("confirm must be exactly 'COMMIT'")
        commit = ET.Element("commit")
        if comment is not None:
            ET.SubElement(commit, "description").text = comment
        root = client.request("commit", cmd=_element_xml(commit))
        meta: dict[str, Any] = {"commit_scope": "firewall" if target_type == "firewall" else "panorama"}
    else:
        if target_type != "panorama":
            raise PanosPackError("commit_all is valid only for Panorama credentials")
        if params.get("confirm") != "COMMIT-ALL":
            raise PanosPackError("confirm must be exactly 'COMMIT-ALL'")
        group = _name(params.get("device_group"), "device_group")
        serials = _string_list(params.get("managed_device_serials", []), "managed_device_serials", names=False, maximum=100)
        serials = [_serial(serial, "managed_device_serials item") for serial in serials]
        commit_all = ET.Element("commit-all")
        shared_policy = ET.SubElement(commit_all, "shared-policy")
        ET.SubElement(shared_policy, "include-template").text = "no"
        device_group = ET.SubElement(shared_policy, "device-group")
        entry = ET.SubElement(device_group, "entry", {"name": group})
        if serials:
            devices = ET.SubElement(entry, "devices")
            for serial in serials:
                ET.SubElement(devices, "entry", {"name": serial})
        if comment is not None:
            ET.SubElement(shared_policy, "description").text = comment
        root = client.request("commit", action="all", cmd=_element_xml(commit_all))
        meta = {"commit_scope": "device_group", "device_group": group, "managed_device_serials": serials}
    job_id = _initial_job(root)
    if job_id is None:
        return {"job_id": None, "status": "FIN", "result": "NO_CHANGES", "polls": 0}, False, meta
    if not wait:
        return {"job_id": job_id, "status": "PEND", "result": None, "polls": 0}, True, meta
    return _poll_job(client, job_id, params), True, meta


def _read_action(client: PanosClient, operation: str, params: dict[str, Any]) -> tuple[Any, None, dict[str, Any]]:
    if operation == "job_status":
        job_id = _string(params.get("job_id"), "job_id", maximum=20)
        if not _JOB_ID.fullmatch(job_id):
            raise PanosPackError("job_id must contain 1 to 20 digits")
        return _job_data(client.op(_job_command(job_id)), job_id), None, {}
    show = ET.Element("show")
    if operation == "system_info":
        system = ET.SubElement(show, "system")
        ET.SubElement(system, "info")
    else:
        config = ET.SubElement(show, "config")
        listing = ET.SubElement(config, "list")
        ET.SubElement(listing, "change-summary")
    root = client.op(show)
    result = root.find("./result")
    return (_xml_data(result) if result is not None else {}), None, {}


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    target_type = _target_type(params)
    timeout = _integer(params, "timeout_seconds", 30, 1, 300)
    credential = _fetch_key(params.get("credential_key", DEFAULT_CREDENTIAL_KEY))
    client = PanosClient(credential, target_type, timeout)
    if any(operation.startswith(f"{kind}_") for kind in _OBJECT_KINDS):
        data, changed, meta = _object_action(client, operation, params, target_type)
    elif operation.startswith("security_rule_"):
        data, changed, meta = _security_action(client, operation, params, target_type)
    elif operation in {"dynamic_address_register", "dynamic_address_unregister"}:
        data, changed, meta = _dynamic_address(client, operation, params, target_type)
    elif operation in {"commit", "commit_all"}:
        data, changed, meta = _commit(client, operation, params, target_type)
    elif operation in _READ_OPERATIONS:
        data, changed, meta = _read_action(client, operation, params)
    else:
        raise PanosPackError("unsupported Palo Alto action")
    return {
        "operation": operation,
        "target_type": target_type,
        "changed": changed,
        "data": data,
        "meta": {"api": "PAN-OS XML API", **meta},
    }
