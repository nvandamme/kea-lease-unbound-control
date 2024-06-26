# kea-lease-unbound-control

Update unbound local data entries from kea leases using unbound-control

Refer to the Kea documentation for the hook points and their arguments:

- <https://kea.readthedocs.io/en/latest/arm/hooks.html#libdhcp-run-script-so-run-script-support-for-external-hook-scripts>

Credits to:

- <https://github.com/zorun/kea-hook-runscript/blob/master/README.md> for Kea's inner working
- <https://stackoverflow.com/users/1009901/yeti> for `sh` compatible ipv6 address handling functions

## Requirements

- Install kea
- Install unbound
- **Ensure that domain-search is setup** via DCHP or on each LAN hosts manually as it is mandaotory for unbound shortname hosts expansion:

```
~ # nslookup foo
Server: 192.168.1.1
Address: 192.168.1.1#53

Non-authoritative answer:
Name:   foo.lan
Address: 192.168.1.2
Name:   foo.lan
Address: fe80::ffff:ffff:dead:beaf
```

```
~ # unbound-control list_local_data | grep foo
foo.lan.    3600    IN  AAAA    fe80::ffff:ffff:dead:beaf
foo.lan.    3600    IN  A 192.168.1.2
2.1.168.192.in-addr.arpa.    3600    IN  PTR    foo.lan.
f.e.e.b.d.a.e.d.f.f.f.f.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.     3600    IN  PTR    foo.lan.
```

## Setup

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

## Configuration

Configure environment variables via `/path/to/kea-lease-unbound-control.sh.env` or your system `etc` default path

```sh
UNBOUND_CONTROL_PATH="/usr/sbin/unbound-control"
UNBOUND_CONFIG_PATH="/etc/unbound/unbound.conf"
UNBOUND_CONTROL_IP="127.0.0.1"
UNBOUND_CONTROL_PORT="953"
LOCAL_DOMAIN="lan"
LOG_ENABLED=1
LOG_FILE="/var/log/kea-lease-unbound-control.log"
```

Config paths by search order:

- /etc/kea/kea-lease-unbound-control.conf
- /etc/kea-lease-unbound-control.conf
- /usr/local/etc/kea/kea-lease-unbound-control.conf
- /usr/local/etc/kea-lease-unbound-control.conf
- /path/to/kea-lease-unbound-control.sh.env
- /etc/default/kea-lease-unbound-control.conf

## PfSense specific configuration

pfSense users can use the pfSense package "Kea DHCP" to configure the hooks by patching /etc/inc/services.inc to activate kea's hooks and call this script

### Configuration file

pfSense configuration file (copy it to /usr/loca/etc/):

- pfSense/usr/local/etc/kea-lease-unbound-control.conf: <https://github.com/nvandamme/kea-lease-unbound-control/blob/main/pfSense/usr/local/etc/kea-lease-unbound-control.conf>

### Patching services.inc

for pfSense 2.7.2-RELEASE:

- pfSense/etc/inc/services.inc.patch: <https://github.com/nvandamme/kea-lease-unbound-control/blob/main/pfSense/etc/inc/services.inc.patch>

### Manual editing services.inc

in /etc/inc/services.inc, add the following lines to the `services_kea4_configure()` function:

```diff
$kea_lease_cmds_hook = [
        'library' => '/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so',
];

+ $kea_run_script_hook = [
+         'library' => '/usr/local/lib/kea/hooks/libdhcp_run_script.so',
+         'parameters' => [
+                 'name' => '/root/kea-lease-unbound-control.sh',
+                 'sync' => false
+         ]
+ ];
+ 
+ $keaconf['Dhcp4']['hooks-libraries'][] = $kea_run_script_hook;
```

in /etc/inc/services.inc, add the following lines to the `services_kea6_configure()` function:

```diff
$kea_lease_cmds_hook = [
        'library' => '/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so',
];

+ $kea_run_script_hook = [
+         'library' => '/usr/local/lib/kea/hooks/libdhcp_run_script.so',
+         'parameters' => [
+                 'name' => '/root/kea-lease-unbound-control.sh',
+                 'sync' => false
+         ]
+ ];
+ 
+ $keaconf['Dhcp6']['hooks-libraries'][] = $kea_run_script_hook;
```
