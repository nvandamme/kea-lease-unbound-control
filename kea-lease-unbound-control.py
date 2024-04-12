#!/usr/bin/env python3

import os
from pathlib import Path
import sys
import subprocess
from datetime import datetime
import ipaddress
from typing import cast

# kea-lease-unbound-control.sh
PROGNAME = os.path.basename(sys.argv[0])

# version
VERSION = "0.1"

# Load environment variables from known locations, stop at first found
config_files = [
    "/etc/kea/kea-lease-unbound-control.conf",
    "/etc/kea-lease-unbound-control.conf",
    "/usr/local/etc/kea/kea-lease-unbound-control.conf",
    "/usr/local/kea-lease-unbound-control.conf",
    "kea-lease-unbound-control.py.env",
    "kea-lease-unbound-control.env",
    "/etc/default/kea-lease-unbound-control.conf",
]


def load_dotenv(dotenv_path: Path) -> None:
    """
    Load environment variables from .env file (key=value pairs, one per line, # for comments, no shell expansion)

    Args:
        dotenv_path (Path): Path to .env file

    Raises:
        FileNotFoundError: If .env file is not found
    """
    with open(dotenv_path) as file:
        for line in file:
            if line.startswith("#"):
                continue
            key, value = line.strip().split("=", 1)
            key = key.strip()
            value = value.strip()
            if key.startswith('"') and key.endswith('"'):
                key = key[1:-1]
            os.environ[key] = value


for file_path in config_files:
    if os.path.isfile(file_path):
        dotenv_path = Path(file_path)
        load_dotenv(dotenv_path=dotenv_path)
        break

# Set default values
UNBOUND_CONTROL_PATH = os.getenv("UNBOUND_CONTROL_PATH", "/usr/sbin/unbound-control")
UNBOUND_CONFIG_PATH = os.getenv("UNBOUND_CONFIG_PATH", "/etc/unbound/unbound.conf")
UNBOUND_CONTROL_IP = os.getenv("UNBOUND_CONTROL_IP", "127.0.0.1")
UNBOUND_CONTROL_PORT = os.getenv("UNBOUND_CONTROL_PORT", "953")
LOCAL_DOMAIN = os.getenv("LOCAL_DOMAIN", "lan")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/kea-lease-unbound-control.log")

UNBOUND_CONTROL = f"{UNBOUND_CONTROL_PATH} -c {UNBOUND_CONFIG_PATH} -s {UNBOUND_CONTROL_IP}@{UNBOUND_CONTROL_PORT}"

HELP = """
Usage: kea-lease-unbound-control.py <kea_hook_point_function> [kea_hook_point_function_arguments]

Script to manage unbound local data entries for kea leases

Refer to the Kea documentation for the hook points and their arguments:
- https://kea.readthedocs.io/en/latest/arm/hooks.html#libdhcp-run-script-so-run-script-support-for-external-hook-scripts

Options:
-h, --help      Display this help and exit
-v, --version   Output version information and exit
-s, --setup     Display setup instructions
"""

SETUP = """
Setup:
- Install kea
- Install unbound
- Configure unbound-control to listen on 127.0.0.1:953
- Configure unbound local_zone with a local domain
```sh
local-zone: "lan." transparent
```
- Configure kea to call this script with the appropriate hook (using kea's default `libdhcp_run_script.so`)
```json
"hooks-libraries": [
    {
        "library": "/usr/local/lib/kea/hooks/libdhcp_run_script.so",
        "parameters": {
            "name": "/usr/local/bin/kea-lease-unbound-control.sh",
            "sync": "false"
        }
    }
]
```
- Configure kea to add DCHP option domain-search match the unbound default local-zone
```json
"option-data": [
        {
           "name": "domain-name-servers",
           "data": "192.168.1.1, fe80::ffff:ffff:ffff:ffff"
        },
        {
            "name": "domain-name",
            "data": "lan"
        }
]
```
- Configure environment variables via `/path/to/kea-lease-unbound-control.sh.env` or your preferred `etc` location
```sh
UNBOUND_CONTROL_PATH="/usr/sbin/unbound-control"
UNBOUND_CONFIG_PATH="/etc/unbound/unbound.conf"
UNBOUND_CONTROL_IP="127.0.0.1"
UNBOUND_CONTROL_PORT="953"
LOCAL_DOMAIN="lan"
LOG_ENABLED=1
LOG_FILE="/var/log/kea-lease-unbound-control.log"
```
- Ensure the config is readable and the script is executable and readable by kea's process user:
```sh
chown kea:kea /path/to/kea-lease-unbound-control.sh
chmod +x /path/to/kea-lease-unbound-control.sh
chown kea:kea /path/to/kea-lease-unbound-control.sh.env
```
"""


def log(message: str) -> None:
    """
    Log message to file

    Args:
        message (str): Message to log
    """
    if os.getenv("LOG_ENABLED") == "1":
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"{datetime.now()} {PROGNAME}: {message}\n")


def get_kea_hook_env_args() -> dict[str, str]:
    """
    Get Kea's hook env arguments as dict

    Returns:
        dict: (str, str) Kea's hook env arguments as dict
    """
    env_args = {}
    for key, value in os.environ.items():
        if (
            key.startswith("QUERY4")
            or key.startswith("QUERY6")
            or key.startswith("LEASE4")
            or key.startswith("LEASE6")
            or key.startswith("LEASES4")
            or key.startswith("LEASES6")
            or key.startswith("DELETED_LEASE4")
            or key.startswith("DELETED_LEASE6")
            or key.startswith("SUBNET4")
            or key.startswith("SUBNET6")
            or key.startswith("PKT4")
            or key.startswith("PKT6")
        ):
            env_args[key] = value
    return env_args


def is_ipv4(ip_str: str) -> bool | ipaddress.IPv4Network:
    """
    Check if string is an IPv4 address

    Args:
        ip_str (str): IP address

    Returns:
        bool: True if string is an IPv4 address, False otherwise
    """
    ip, _ = ip_str.split("/") if "/" in ip_str else (ip_str, "")
    try:
        return ipaddress.IPv4Network(ip, strict=False)
    except ValueError:
        return False


def ip_to_ptr(ip_str: str) -> str | None:
    """
    Convert IPv4 address to PTR record

    Args:
        ip_str (str): IP address

    Returns:
        str: PTR record
    """
    ip = is_ipv4(ip_str)
    if not is_ipv4(ip_str):
        return None
    return cast(ipaddress.IPv4Network, ip).reverse_pointer


def is_ipv6(ip_str: str) -> bool | ipaddress.IPv6Network:
    """
    Check if string is an IPv6 address

    Args:
        ip_str (str): IP address

    Returns:
        bool: True if string is an IPv6 address, False otherwise
    """
    try:
        return ipaddress.IPv6Network(ip_str, strict=False)
    except ValueError:
        return False


def expand_ipv6(ip_str: str) -> str | None:
    """
    Expand IPv6 address

    Args:
        ip_str (str): IPv6 address

    Returns:
        str: Expanded IPv6 address
    """
    ip = is_ipv6(ip_str)
    if not is_ipv6(ip_str):
        return None
    return cast(ipaddress.IPv6Network, ip).exploded


def compress_ipv6(ip_str: str) -> str:
    """
    Compress IPv6 address

    Args:
        ip_str (str): IPv6 address

    Returns:
        str: Compressed IPv6 address
    """
    ip = is_ipv6(ip_str)
    if not is_ipv6(ip_str):
        return ip_str
    return cast(ipaddress.IPv6Network, ip).compressed


def clean_hostname(hostname: str) -> str:
    """
    Clean hostname for local data entry (remove trailing dot, replace dots with hyphens)

    Args:
        hostname (str): Hostname

    Returns:
        str: Cleaned hostname
    """
    return hostname.rstrip(".").replace(".", "-")


def ip6_to_ptr6(ip_str: str) -> str | None:
    """
    Convert IPv6 address to PTR record

    Args:
        ip_str (str): IPv6 address

    Returns:
        str: PTR record
    """
    ip = is_ipv6(ip_str)
    if not ip:
        return None
    return cast(ipaddress.IPv6Network, ip).reverse_pointer


def ptr_to_ip(ptr_str: str) -> ipaddress.IPv4Network | None:
    """
    Convert PTR record to IPv4 address

    Args:
        ptr_str (str): PTR record

    Returns:
        str: IPv4 address
    """
    parts = ptr_str.split(".")
    if parts[-2:] != ["in-addr", "arpa"]:
        return None
    ip_parts = [parts[i] for i in range(len(parts) - 3, -1, -1)]
    ip = None
    try:
        ip = ipaddress.IPv4Network(".".join(ip_parts), strict=False)
    except ipaddress.AddressValueError:
        return None
    return ip


def ptr6_to_ip6(ptr_str: str) -> ipaddress.IPv6Network | None:
    """
    Convert PTR record to IPv6 address

    Args:
        ptr_str (str): PTR record

    Returns:
        str: IPv6 address
    """
    parts = ptr_str.split(".")
    if parts[-1] != "ip6.arpa":
        return None
    ip_parts = [parts[i] for i in range(len(parts) - 2, -1, -1)]
    ip_str = ":".join(
        ["".join(ip_parts[i : i + 4]) for i in range(0, len(ip_parts), 4)]
    )
    ip = None
    try:
        ip = ipaddress.IPv6Network(ip_str, strict=False)
    except ipaddress.AddressValueError:
        return None
    return ip


def unbound_control_exec(command: str, *args: str) -> tuple[bool, str]:
    """
    Run unbound-control command

    Args:
    command (str): unbound-control command
    args (str): unbound-control command arguments

    Returns:
    str: unbound-control command output
    """
    result = subprocess.run([UNBOUND_CONTROL, command, *args], capture_output=True)
    if result.returncode != 0:
        log(f"Failed to run unbound-control {command} {' '.join(args)}")
        return (
            False,
            (
                result.stderr.decode("utf-8")
                if result.stderr
                else result.stdout.decode("utf-8")
            ),
        )
    if result.stdout.decode("utf-8").startswith("error"):
        log(f"Failed to run unbound-control {command} {' '.join(args)}")
        return (False, result.stderr.decode("utf-8"))
    return (True, result.stdout.decode("utf-8"))


def add_lease4(hostname: str, ipv4_address: str) -> None:
    """
    Add lease4 entry to unbound local data

    Args:
    hostname (str): Hostname (LEASE4_HOSTNAME)
    ipv4_address (str): IPv4 address (LEASE4_ADDRESS)
    """
    HOSTNAME = clean_hostname(hostname)
    log(f"Adding A and PTR records for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv4_address}")
    PTR = ip_to_ptr(ipv4_address)
    if not PTR:
        log(f"Invalid IPv4 address: {ipv4_address}")
        return None
    result = unbound_control_exec(
        "local_data", f"{HOSTNAME}.{LOCAL_DOMAIN}", "A", ipv4_address
    )
    if result[0] and result[1].startswith("ok"):
        log(f"Added A record for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv4_address}")
        result = unbound_control_exec("local_data", PTR, "PTR", HOSTNAME)
        if result[0] and result[1].startswith("ok"):
            log(f"Added PTR record for {HOSTNAME}.{LOCAL_DOMAIN} -> {PTR}")


def del_lease4(hostname: str, ipv4_address: str) -> None:
    """
    Remove lease4 entry from unbound local data

    Args:
    hostname (str): Hostname (LEASE4_HOSTNAME)
    ipv4_address (str): IPv4 address (LEASE4_ADDRESS)
    """
    HOSTNAME = clean_hostname(hostname)
    log(f"Removing A and PTR records for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv4_address}")
    PTR = ip_to_ptr(ipv4_address)
    if not PTR:
        log(f"Invalid IPv4 address: {ipv4_address}")
        return None
    result = unbound_control_exec(
        "local_data_remove", f"{HOSTNAME}.{LOCAL_DOMAIN}", "A", ipv4_address
    )
    if result[0] and result[1].startswith("ok"):
        log(f"Removed A record for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv4_address}")
        result = unbound_control_exec("local_data_remove", PTR, "PTR", HOSTNAME)
        if result[0] and result[1].startswith("ok"):
            log(f"Removed PTR record for {PTR} -> {HOSTNAME}.{LOCAL_DOMAIN}")


def add_lease6(
    hostname: str, ipv6_address: str, ipv6_local_address: str | None = None
) -> None:
    """
    Add lease6 entry to unbound local data

    Args:
    hostname (str): Hostname (LEASE6_HOSTNAME)
    ipv6_address (str): IPv6 address (LEASE6_ADDRESS)
    ipv6_local_address (str, optional): IPv6 local address (QUERY6_REMOTE_ADDR)
    """
    HOSTNAME = clean_hostname(hostname)
    log(f"Adding AAAA and PTR records for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv6_address}")
    PTR6 = ip6_to_ptr6(ipv6_address)
    if not PTR6:
        log(f"Invalid IPv6 address: {ipv6_address}")
        return None
    result = unbound_control_exec(
        "local_data", f"{HOSTNAME}.{LOCAL_DOMAIN}", "AAAA", ipv6_address
    )
    if result[0] and result[1].startswith("ok"):
        log(f"Added AAAA record for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv6_address}")
        result = unbound_control_exec("local_data", PTR6, "PTR", HOSTNAME)
        if result[0] and result[1].startswith("ok"):
            log(f"Added PTR record for {HOSTNAME}.{LOCAL_DOMAIN} -> {PTR6}")
    if ipv6_local_address:
        PTR6LOCAL = ip6_to_ptr6(ipv6_local_address)
        if not PTR6LOCAL:
            log(f"Invalid IPv6 address: {ipv6_local_address}")
            return None
        result = unbound_control_exec(
            "local_data", f"{HOSTNAME}.{LOCAL_DOMAIN}", "AAAA", ipv6_local_address
        )
        if result[0] and result[1].startswith("ok"):
            log(
                f"Added AAAA record for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv6_local_address}"
            )
            result = unbound_control_exec("local_data", PTR6LOCAL, "PTR", HOSTNAME)
            if result[0] and result[1].startswith("ok"):
                log(f"Added PTR record for {HOSTNAME}.{LOCAL_DOMAIN} -> {PTR6LOCAL}")


def del_lease6(
    hostname: str, ipv6_address: str, ipv6_local_address: str | None = None
) -> None:
    """
    Remove lease6 entry from unbound local data

    Args:
    hostname (str): Hostname (LEASE6_HOSTNAME)
    ipv6_address (str): IPv6 address (LEASE6_ADDRESS)
    ipv6_local_address (str, optional): IPv6 local address (QUERY6_REMOTE_ADDR)
    """
    HOSTNAME = clean_hostname(hostname)
    log(
        f"Removing AAAA and PTR records for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv6_address}"
    )
    PTR6 = ip6_to_ptr6(ipv6_address)
    if not PTR6:
        log(f"Invalid IPv6 address: {ipv6_address}")
        return None
    result = unbound_control_exec(
        "local_data_remove", f"{HOSTNAME}.{LOCAL_DOMAIN}", "AAAA", ipv6_address
    )
    if result[0] and result[1].startswith("ok"):
        log(f"Removed AAAA record for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv6_address}")
        result = unbound_control_exec("local_data_remove", PTR6, "PTR", HOSTNAME)
        if result[0] and result[1].startswith("ok"):
            log(f"Removed PTR record for {PTR6} -> {HOSTNAME}.{LOCAL_DOMAIN}")
    if ipv6_local_address:
        PTR6LOCAL = ip6_to_ptr6(ipv6_local_address)
        if not PTR6LOCAL:
            log(f"Invalid IPv6 address: {ipv6_local_address}")
            return None
        result = unbound_control_exec(
            "local_data_remove",
            f"{HOSTNAME}.{LOCAL_DOMAIN}",
            "AAAA",
            ipv6_local_address,
        )
        if result[0] and result[1].startswith("ok"):
            log(
                f"Removed AAAA record for {HOSTNAME}.{LOCAL_DOMAIN} -> {ipv6_local_address}"
            )
            result = unbound_control_exec(
                "local_data_remove", PTR6LOCAL, "PTR", HOSTNAME
            )
            if result[0] and result[1].startswith("ok"):
                log(f"Removed PTR record for {PTR6LOCAL} -> {HOSTNAME}.{LOCAL_DOMAIN}")


def handle_add_lease4(env: dict[str, str] | None = None) -> None:
    """
    Add lease4 entry to unbound local data
    """
    env = get_kea_hook_env_args() if env is None else env
    keys = env.keys()
    if len(keys) == 0:
        log("No environment arguments found")
        return None
    if "LEASE4_ADDRESS" in keys and "LEASE4_HOSTNAME" in keys:
        LEASE4_ADDRESS = env["LEASE4_ADDRESS"]
        LEASE4_HOSTNAME = env["LEASE4_HOSTNAME"]
        add_lease4(LEASE4_HOSTNAME, LEASE4_ADDRESS)


def handle_del_lease4(env: dict[str, str] | None = None) -> None:
    """
    Remove lease4 entry from unbound local data
    """
    env = get_kea_hook_env_args() if env is None else env
    keys = env.keys()
    if len(keys) == 0:
        log("No environment arguments found")
        return None
    if "LEASE4_ADDRESS" in keys and "LEASE4_HOSTNAME" in keys:
        LEASE4_ADDRESS = env["LEASE4_ADDRESS"]
        LEASE4_HOSTNAME = env["LEASE4_HOSTNAME"]
        del_lease4(LEASE4_HOSTNAME, LEASE4_ADDRESS)


def handle_add_lease6(env: dict[str, str] | None = None) -> None:
    """
    Add lease6 entry to unbound local data
    """
    env = get_kea_hook_env_args() if env is None else env
    keys = env.keys()
    if len(keys) == 0:
        log("No environment arguments found")
        return None
    if "LEASE6_ADDRESS" in keys and "LEASE6_HOSTNAME" in keys:
        LEASE6_ADDRESS = env["LEASE6_ADDRESS"]
        LEASE6_HOSTNAME = env["LEASE6_HOSTNAME"]
        if "QUERY6_REMOTE_ADDR" in keys:
            QUERY6_REMOTE_ADDR = env["QUERY6_REMOTE_ADDR"]
            add_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS, QUERY6_REMOTE_ADDR)
        else:
            add_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS)


def handle_del_lease6(env: dict[str, str] | None = None) -> None:
    """
    Remove lease6 entry from unbound local data
    """
    env = get_kea_hook_env_args() if env is None else env
    keys = env.keys()
    if len(keys) == 0:
        log("No environment arguments found")
        return None
    if "LEASE6_ADDRESS" in keys and "LEASE6_HOSTNAME" in keys:
        LEASE6_ADDRESS = env["LEASE6_ADDRESS"]
        LEASE6_HOSTNAME = env["LEASE6_HOSTNAME"]
        if "QUERY6_REMOTE_ADDR" in keys:
            QUERY6_REMOTE_ADDR = env["QUERY6_REMOTE_ADDR"]
            del_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS, QUERY6_REMOTE_ADDR)
        else:
            del_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS)


def unknown_handle(args: list[str]) -> None:
    print("Unknown command:", " ".join(args))
    sys.exit(1)


def lease4_renew() -> None:
    """
    Renews the IPv4 lease for the specified hostname and address.
    """
    handle_add_lease4()


def lease4_expire() -> None:
    """
    Expires the IPv4 lease for the specified hostname and address.
    """
    handle_del_lease4()


def lease4_recover() -> None:
    """
    Recovers the IPv4 lease for the specified hostname and address.
    """
    handle_add_lease4()


def leases4_committed() -> None:
    """
    Handles committed IPv4 leases and deleted IPv4 leases.
    """
    env = get_kea_hook_env_args()
    keys = env.keys()
    if len(keys) == 0:
        log("No environment arguments found")
        return None

    if "LEASES4_SIZE" in keys:
        LEASES4_SIZE = int(env["LEASES4_SIZE"])
        MAX_LEASES = LEASES4_SIZE - 1
        SEQ = range(LEASES4_SIZE)
    else:
        LEASES4_SIZE = 0

    if LEASES4_SIZE > 0:
        for i in SEQ:
            if f"LEASES4_AT{i}_HOSTNAME" in keys and f"LEASES4_AT{i}_ADDRESS" in keys:
                LEASE4_HOSTNAME = env[f"LEASES4_AT{i}_HOSTNAME"]
                LEASE4_ADDRESS = env[f"LEASES4_AT{i}_HOSTNAME"]
                log(f"Committed lease4 {LEASE4_ADDRESS} for {LEASE4_HOSTNAME}")
                add_lease4(LEASE4_HOSTNAME, LEASE4_ADDRESS)
    elif "LEASE4_ADDRESS" in keys and "LEASE4_HOSTNAME" in keys:
        LEASE4_ADDRESS = env["LEASE4_ADDRESS"]
        LEASE4_HOSTNAME = env["LEASE4_HOSTNAME"]
        log(f"Committed lease4 {LEASE4_ADDRESS} for {LEASE4_HOSTNAME}")
        add_lease4(LEASE4_HOSTNAME, LEASE4_ADDRESS)

    if "DELETED_LEASES4_SIZE" in keys:
        DELETED_LEASES4_SIZE = int(env["DELETED_LEASES4_SIZE"])
        MAX_LEASES = DELETED_LEASES4_SIZE - 1
        SEQ = range(DELETED_LEASES4_SIZE)
    else:
        DELETED_LEASES4_SIZE = 0

    if DELETED_LEASES4_SIZE > 0:
        for i in SEQ:
            if (
                f"DELETED_LEASES4_AT{i}_HOSTNAME" in keys
                and f"DELETED_LEASES4_AT{i}_ADDRESS" in keys
            ):
                DELETED_LEASE4_HOSTNAME = env[f"DELETED_LEASES4_AT{i}_HOSTNAME"]
                DELETED_LEASE4_ADDRESS = env[f"DELETED_LEASES4_AT{i}_ADDRESS"]
                log(
                    f"Deleted lease4 {DELETED_LEASE4_ADDRESS} for {DELETED_LEASE4_HOSTNAME}"
                )
                del_lease4(DELETED_LEASE4_HOSTNAME, DELETED_LEASE4_ADDRESS)
    elif "DELETED_LEASE4_ADDRESS" in keys and "DELETED_LEASE4_HOSTNAME" in keys:
        DELETED_LEASE4_ADDRESS = env["DELETED_LEASE4_ADDRESS"]
        DELETED_LEASE4_HOSTNAME = env["DELETED_LEASE4_HOSTNAME"]
        log(f"Deleted lease4 {DELETED_LEASE4_ADDRESS} for {DELETED_LEASE4_HOSTNAME}")
        del_lease4(DELETED_LEASE4_HOSTNAME, DELETED_LEASE4_ADDRESS)


def lease4_release() -> None:
    """
    Releases the IPv4 lease for the specified hostname and address.
    """
    handle_del_lease4()


def lease4_decline() -> None:
    """
    Handles the decline of an IPv4 lease.
    """
    return None


def lease6_renew() -> None:
    """
    Renews an IPv6 lease.
    """
    handle_add_lease6()


def lease6_rebind() -> None:
    """
    Rebinds an IPv6 lease.
    """
    handle_add_lease6()


def lease6_expire() -> None:
    """
    Expires an IPv6 lease.
    """
    handle_del_lease6()


def lease6_recover() -> None:
    """
    Recovers an IPv6 lease.
    """
    handle_add_lease6()


def leases6_committed():
    """
    Commits IPv6 leases.
    """
    env = get_kea_hook_env_args()
    keys = env.keys()
    if len(keys) == 0:
        log("No environment arguments found")
        return None

    if "LEASES6_SIZE" in keys:
        LEASES6_SIZE = int(env["LEASES6_SIZE"])
        MAX_LEASES = LEASES6_SIZE - 1
        SEQ = range(LEASES6_SIZE)
    else:
        LEASES6_SIZE = 0

    if LEASES6_SIZE > 0:
        MAX_LEASES = LEASES6_SIZE - 1
        SEQ = range(MAX_LEASES + 1)
        for i in SEQ:
            if f"LEASES6_AT{i}_ADDRESS" in keys and f"LEASES6_AT{i}_HOSTNAME" in keys:
                LEASE6_ADDRESS = env[f"LEASES6_AT{i}_ADDRESS"]
                LEASE6_HOSTNAME = env[f"LEASES6_AT{i}_HOSTNAME"]
                if "QUERY6_REMOTE_ADDR" in keys:
                    QUERY6_REMOTE_ADDR = env["QUERY6_REMOTE_ADDR"]
                    log(
                        f"Committed lease6 {LEASE6_ADDRESS}, {QUERY6_REMOTE_ADDR} for {LEASE6_HOSTNAME}"
                    )
                    add_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS, QUERY6_REMOTE_ADDR)
                else:
                    log(f"Committed lease6 {LEASE6_ADDRESS} for {LEASE6_HOSTNAME}")
                    add_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS)
    elif "LEASE6_ADDRESS" in keys and "LEASE6_HOSTNAME" in keys:
        LEASE6_ADDRESS = env["LEASE6_ADDRESS"]
        LEASE6_HOSTNAME = env["LEASE6_HOSTNAME"]
        if "QUERY6_REMOTE_ADDR" in keys:
            QUERY6_REMOTE_ADDR = env["QUERY6_REMOTE_ADDR"]
            log(
                f"Committed lease6 {LEASE6_ADDRESS}, {QUERY6_REMOTE_ADDR} for {LEASE6_HOSTNAME}"
            )
            add_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS, QUERY6_REMOTE_ADDR)
        else:
            log(f"Committed lease6 {LEASE6_ADDRESS} for {LEASE6_HOSTNAME}")
            add_lease6(LEASE6_HOSTNAME, LEASE6_ADDRESS)

    if "DELETED_LEASES6_SIZE" in keys:
        DELETED_LEASES6_SIZE = int(env["DELETED_LEASES6_SIZE"])
        MAX_LEASES = DELETED_LEASES6_SIZE - 1
        SEQ = range(DELETED_LEASES6_SIZE)
    else:
        DELETED_LEASES6_SIZE = 0

    if DELETED_LEASES6_SIZE > 0:
        MAX_LEASES = DELETED_LEASES6_SIZE - 1
        SEQ = range(MAX_LEASES + 1)
        for i in SEQ:
            if (
                f"DELETED_LEASES6_AT{i}_ADDRESS" in keys
                and f"DELETED_LEASES6_AT{i}_HOSTNAME" in keys
            ):
                DELETED_LEASE6_ADDRESS = env[f"DELETED_LEASES6_AT{i}_ADDRESS"]
                DELETED_LEASE6_HOSTNAME = env[f"DELETED_LEASES6_AT{i}_HOSTNAME"]
                if "QUERY6_REMOTE_ADDR" in keys:
                    QUERY6_REMOTE_ADDR = env["QUERY6_REMOTE_ADDR"]
                    log(
                        f"Deleted lease6 {DELETED_LEASE6_ADDRESS}, {QUERY6_REMOTE_ADDR} for {DELETED_LEASE6_HOSTNAME}"
                    )
                    del_lease6(
                        DELETED_LEASE6_HOSTNAME,
                        DELETED_LEASE6_ADDRESS,
                        QUERY6_REMOTE_ADDR,
                    )
                else:
                    log(
                        f"Deleted lease6 {DELETED_LEASE6_ADDRESS} for {DELETED_LEASE6_HOSTNAME}"
                    )
                    del_lease6(DELETED_LEASE6_HOSTNAME, DELETED_LEASE6_ADDRESS)
    elif "DELETED_LEASE6_ADDRESS:" in keys and "DELETED_LEASE6_HOSTNAME" in keys:
        DELETED_LEASE6_ADDRESS = env["DELETED_LEASE6_ADDRESS"]
        DELETED_LEASE6_HOSTNAME = env["DELETED_LEASE6_HOSTNAME"]
        if "QUERY6_REMOTE_ADDR" in keys:
            QUERY6_REMOTE_ADDR = env["QUERY6_REMOTE_ADDR"]
            log(
                f"Deleted lease6 {DELETED_LEASE6_ADDRESS}, {QUERY6_REMOTE_ADDR} for {DELETED_LEASE6_HOSTNAME}"
            )
            del_lease6(
                DELETED_LEASE6_HOSTNAME, DELETED_LEASE6_ADDRESS, QUERY6_REMOTE_ADDR
            )
        else:
            log(
                f"Deleted lease6 {DELETED_LEASE6_ADDRESS} for {DELETED_LEASE6_HOSTNAME}"
            )
            del_lease6(DELETED_LEASE6_HOSTNAME, DELETED_LEASE6_ADDRESS)


def lease6_release() -> None:
    """
    Releases an IPv6 lease.
    """
    handle_del_lease6()


def lease6_decline() -> None:
    """
    Declines an IPv6 lease.
    """
    return None


if __name__ == "__main__":

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "lease4_renew":
            lease4_renew()
        elif command == "lease4_expire":
            lease4_expire()
        elif command == "lease4_recover":
            lease4_recover()
        elif command == "leases4_committed":
            leases4_committed()
        elif command == "lease4_release":
            lease4_release()
        elif command == "lease4_decline":
            lease4_decline()
        elif command == "lease6_renew":
            lease6_renew()
        elif command == "lease6_rebind":
            lease6_rebind()
        elif command == "lease6_expire":
            lease6_expire()
        elif command == "lease6_recover":
            lease6_recover()
        elif command == "leases6_committed":
            leases6_committed()
        elif command == "lease6_release":
            lease6_release()
        elif command == "lease6_decline":
            lease6_decline()
        elif command in ["-h", "--help"]:
            print(HELP)
            sys.exit(0)
        elif command in ["-v", "--version"]:
            print(f"{PROGNAME} {VERSION}")
            sys.exit(0)
        elif command in ["-s", "--setup"]:
            print(SETUP)
            sys.exit(0)
        else:
            unknown_handle(sys.argv[1:])
    else:
        print(HELP)
        sys.exit(0)
