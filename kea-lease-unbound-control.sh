#!/bin/sh

###
kea-lease-unbound-control.sh
https://github.com/nvandamme/kea-lease-unbound-control
Licence: GPL3
###

# kea-lease-unbound-control.sh
PROGNAME="$(basename $0)"

# version
VERSION="0.1"

# Load environment variables from known locations
if [ -f "/etc/kea/kea-lease-unbound-control.conf" ]; then
    . "/etc/kea/kea-lease-unbound-control.conf"
elif [ -f "/etc/kea-lease-unbound-control.conf" ]; then
    . "/etc/kea-lease-unbound-control.conf"
elif [ -f "/usr/local/etc/kea/kea-lease-unbound-control.conf" ]; then
    . "/usr/local/etc/kea/kea-lease-unbound-control.conf"
elif [ -f "/usr/local/etc/kea-lease-unbound-control.conf" ]; then
    . "/usr/local/etc/kea-lease-unbound-control.conf"
elif [ -f "$0.env" ]; then
    . "$0.env"
elif [ -f "/etc/default/kea-lease-unbound-control.conf" ]; then
    . "/etc/default/kea-lease-unbound-control.conf"
fi

# Set default values
if [ -z "$UNBOUND_CONTROL_PATH" ]; then
    UNBOUND_CONTROL_PATH="/usr/sbin/unbound-control"
fi
if [ -z "$UNBOUND_CONFIG_PATH" ]; then
    UNBOUND_CONFIG_PATH="/etc/unbound/unbound.conf"
fi
if [ -z "$UNBOUND_CONTROL_IP" ]; then
    UNBOUND_CONTROL_IP="127.0.0.1"
fi
if [ -z "$UNBOUND_CONTROL_PORT" ]; then
    UNBOUND_CONTROL_PORT="953"
fi
if [ -z "log_FILE" ]; then
    LOG_FILE="/var/log/kea-lease-unbound-control.log"
fi

# Set unbound-control command
UNBOUND_CONTROL="${UNBOUND_CONTROL_PATH} -c ${UNBOUND_CONFIG_PATH} -s ${UNBOUND_CONTROL_IP}@${UNBOUND_CONTROL_PORT}"

# Display help
HELP=$(cat <<-'EOF'
Usage: kea-lease-unbound-control.sh <kea_hook_point_function> [kea_hook_point_function_arguments]

Script to manage unbound local data entries for kea leases

Refer to the Kea documentation for the hook points and their arguments:
- https://kea.readthedocs.io/en/latest/arm/hooks.html#libdhcp-run-script-so-run-script-support-for-external-hook-scripts

Setup:
- Install kea
- Install unbound
- Configure unbound-control to listen on 127.0.0.1:953
- Configure unbound local_zone with a local domain, e.g.:
    - local-zone: "local." transparent
- Configure kea to call this script with the appropriate hook: 
    "hooks-libraries": [
        {
            "library": "/usr/local/lib/kea/hooks/libdhcp_run_script.so",
            "parameters": {
                "name": "/usr/local/bin/kea-lease-unbound-control.sh",
                "sync": "false"
            }
        }
    ]
- pfSense users can use the pfSense package "Kea DHCP" to configure the hooks by modifiying /etc/inc/services.inc to activate kea's hooks and call this script
    - in /etc/inc/services.inc, add the following lines to the `services_kea4_configure()` function:
    ```php 
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
    - in /etc/inc/services.inc, add the following lines to the `services_kea6_configure()` function:
    ```php 
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
- Configure environment variables via `/path/to/kea-lease-unbound-control.sh.env` or yout preferred `etc` location:
    UNBOUND_CONTROL_PATH="/usr/sbin/unbound-control"
    UNBOUND_CONFIG_PATH="/etc/unbound/unbound.conf"
    UNBOUND_CONTROL_IP="127.0.0.1"
    UNBOUND_CONTROL_PORT="953"
    LOG_ENABLED=1
    LOG_FILE="/var/log/kea-lease-unbound-control.log"

Options:
-h, --help      Display this help and exit
-v, --version   Output version information and exit
EOF
)

# Log function
log() {
    if [ $LOG_ENABLED=1 ]; then
        echo "$(date) ${PROGNAME}: ${*}" >> $LOG_FILE
    fi
}

# Check if string is an IPv4 address
is_ipv4() {
	echo $1 |\
		grep -qs "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" ||\
		return 1
	return 0
}

# Convert IPv4 address to PTR record
ip_to_ptr() {
    echo $1 | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}'
}

# Expand IPv6 address
# > https://stackoverflow.com/questions/14697403/expand-ipv6-address-in-shell-script
# > credits to https://stackoverflow.com/users/1009901/yeti
expand_ipv6() {
  __expand_ipv6_ip="${1%%/*}"
  __expand_ipv6_mask=""

  case "$1" in
    */*)
      __expand_ipv6_mask="${1#*/}"
      __expand_ipv6_mask="/${__expand_ipv6_mask%%[^0-9/]*}"
  esac

  case "$__expand_ipv6_ip" in
    :*) __expand_ipv6_ip="0$__expand_ipv6_ip"
  esac

  case "$__expand_ipv6_ip" in
    *::*)
      __expand_ipv6_colons="$(echo "$__expand_ipv6_ip" | tr -c -d ':')"
      __expand_ipv6_expanded="$(echo ":::::::::" | sed -e "s/$__expand_ipv6_colons//" -e 's/:/:0/g')"
      __expand_ipv6_ip="$(echo "$__expand_ipv6_ip" | sed "s/::/$__expand_ipv6_expanded/")"
    ;;
  esac

  __expand_ipv6_blocks="$(echo "$__expand_ipv6_ip" | grep -o '[0-9a-f]\+' | while read -r __expand_ipv6_hex; do [ -n "$__expand_ipv6_hex" ] && printf " %d" "$((0x$__expand_ipv6_hex % 65536))"; done)"
  printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x" $__expand_ipv6_blocks
  printf "%s\n" "$__expand_ipv6_mask"
}

# Compress IPv6 address
# > https://stackoverflow.com/questions/14697403/expand-ipv6-address-in-shell-script
# > credits to https://stackoverflow.com/users/1009901/yeti
compress_ipv6() {
  __compress_ipv6_ip="$(echo "$1" | sed -e 's/::/:0:/g' | grep -o "[0-9a-f]\+" | while read -r __compress_ipv6_hex; do [ -n "$__compress_ipv6_hex" ] && printf ":%x" "$((0x$__compress_ipv6_hex))"; done)"

  for __compress_ipv6_chain in :0:0:0:0:0:0:0:0 :0:0:0:0:0:0:0 :0:0:0:0:0:0 :0:0:0:0:0 :0:0:0:0 :0:0:0 :0:0 :0
  do
    case "$__compress_ipv6_ip" in
      *$__compress_ipv6_chain*)
        __compress_ipv6_ip="$(echo "$__compress_ipv6_ip" | sed -e "s/$__compress_ipv6_chain/::/" -e 's/:::/::/')"
        break
    esac
  done

  case "$__compress_ipv6_ip" in
    ::*) ;;
    :*) __compress_ipv6_ip="${__compress_ipv6_ip#:}"
  esac
  echo "$__compress_ipv6_ip"
}

# Check if string is an IPv6 address
is_ipv6() {
    echo $1 |\
        grep -qs "[0-9a-f:]\{1,39\}" ||\
        return 1
    return 0
}

# Clean hostname for local data entry (remove trailing dot, replace dots with hyphens)
clean_hostname() { 
    echo "$1" | sed 's/\.$//' | sed 's/\./-/'
}

# Convert IPv6 address to PTR record
ip6_to_ptr6() {
    is_ipv6 $1 || return 1
    expanded=$(expand_ipv6 $1)
    echo $expanded | awk -F: '{
        gsub(/:/,"")
        for (i=length($0); i>0; i--) {
            printf "%s.", substr($0,i,1)
        }
        print "ip6.arpa"
    }'
}

# Convert PTR record to IPv4 address
ptr_to_ip() {
    echo $1 | awk -F. '{print $4"."$3"."$2"."$1}'
}

# Convert PTR record to IPv6 address
ptr6_to_ip6() {
    echo $1 | awk -F. '{print $32$31$30$29":"$28$27$26$25":"$24$23$22$21":"$20$19$18$17":"$16$15$14$13":"$12$11$10$9":"$8$7$6$5":"$4$3$2$1}'
}

# Handle unknown function calls
unknown_handle() {
    echo "Unhandled function call ${*}"
    exit 123
}

# Add lease4 entry to unbound local data
add_lease4() {
    # $1 = hostname (LEASE4_HOSTNAME)
    # $2 = ipv4 address (LEASE4_ADDRESS)
    HOSTNAME=$(clean_hostname $1)
    log "Adding A and PTR records for ${HOSTNAME} -> $2"
    PTR=$(ip_to_ptr $2)
    $UNBOUND_CONTROL local_data "${HOSTNAME}" A "${2}"
    $UNBOUND_CONTROL local_data "${ptr}" PTR "${HOSTNAME}"
    log "Added A and PTR records for ${HOSTNAME} -> $2 -> ${PTR}"
}

# Remove lease4 entry from unbound local data
del_lease4() {
    # $1 = hostname (LEASE4_HOSTNAME)
    # $2 = ipv4 address (LEASE4_ADDRESS)
    HOSTNAME=$(clean_hostname $1)
    log "Removing A and PTR records for ${HOSTNAME} -> $2"
    PTR=$(ip_to_ptr $2)
    $UNBOUND_CONTROL local_data_remove "${HOSTNAME}" A "${2}"
    $UNBOUND_CONTROL local_data_remove "${ptr}" PTR "${HOSTNAME}"
    log "Removed A and PTR records for ${HOSTNAME} -> $2 -> ${PTR}"
}

# Add lease6 entry to unbound local data
add_lease6() {
    # $1 = hostname (LEASE6_HOSTNAME)
    # $2 = ipv6 address (LEASE6_ADDRESS)
    HOSTNAME=$(clean_hostname $1)
    log "Adding AAAA and PTR records for ${HOSTNAME} -> $2"
    PTR6=$(ip6_to_ptr6 $2)
    $UNBOUND_CONTROL local_data "${HOSTNAME}" AAAA "${2}"
    $UNBOUND_CONTROL local_data "${PTR6}" PTR "${HOSTNAME}"
    if [ $3 ]; then
        PTR6LOCAL=$(ip6_to_ptr6 $3)
        $UNBOUND_CONTROL local_data "${HOSTNAME}" AAAA "${3}"
        $UNBOUND_CONTROL local_data "${PTR6LOCAL}" PTR "${HOSTNAME}"
        log "Added AAAA and PTR records for ${HOSTNAME} -> $2, $3 -> ${PTR6}, ${PTR6LOCAL}"
    else
        log "Added AAAA and PTR records for ${HOSTNAME} -> $2, $3 -> ${PTR6}"
    fi
}

# Remove lease6 entry from unbound local data
del_lease6() {
    # $1 = hostname (LEASE6_HOSTNAME)
    # $2 = ipv6 address (LEASE6_ADDRESS)
    HOSTNAME=$(clean_hostname $1)
    log "Removing AAAA and PTR records for ${HOSTNAME} -> $2"
    PTR6=$(ip6_to_ptr6 $2)
    $UNBOUND_CONTROL local_data_remove "${HOSTNAME}" AAAA "${2}"
    $UNBOUND_CONTROL local_data_remove "${PTR6}" PTR "${HOSTNAME}"
    if [ $3 ]; then
        PTR6LOCAL=$(ip6_to_ptr6 $3)
        $UNBOUND_CONTROL local_data_remove "${HOSTNAME}" AAAA "${3}"
        $UNBOUND_CONTROL local_data_remove "${PTR6LOCAL}" PTR "${HOSTNAME}"
        log "Removed AAAA and PTR records for ${HOSTNAME} -> $2, $3 -> ${PTR6}, ${PTR6LOCAL}"
    else
        log "Removed AAAA and PTR records for ${HOSTNAME} -> $2 -> ${PTR6}"
    fi
}

# Handle kea hook point lease4_renew
lease4_renew () {
    log "Renewing lease4 ${LEASE4_ADDRESS} for ${LEASE4_HOSTNAME}"
    add_lease4 $LEASE4_HOSTNAME $LEASE4_ADDRESS
    return 0 # handled by leases4_committed in case of multiple leases
}

# Handle kea hook point lease4_expire
lease4_expire () {
    log "Expiring lease4 ${LEASE4_ADDRESS} for ${LEASE4_HOSTNAME}"
    del_lease4 $LEASE4_HOSTNAME $LEASE4_ADDRESS
    return 0 # handled by leases4_committed in case of multiple leases
}

# Handle kea hook point lease4_recover
lease4_recover () {
    log "Recovering lease4 ${LEASE4_ADDRESS} for ${LEASE4_HOSTNAME}"
    add_lease4 $LEASE4_HOSTNAME $LEASE4_ADDRESS
    return 0 # handled by leases4_committed in case of multiple leases
}

# Handle kea hook point leases4_committed
leases4_committed () {
    if [ $LEASES4_SIZE -gt 0 ]; then
        MAX_LEASES=$((${LEASES4_SIZE} - 1))
        SEQ=$(seq 0 $MAX_LEASES)
        for i in $SEQ; do
            LEASE4_HOSTNAME=$(eval echo "\$LEASES4_AT${i}_HOSTNAME")
            LEASE4_ADDRESS=$(eval echo "\$LEASES4_AT${i}_ADDRESS")
            log "Committed lease4 ${LEASE4_ADDRESS} for ${LEASE4_HOSTNAME}"
            add_lease4 $LEASE4_HOSTNAME $LEASE4_ADDRESS
        done
    elif [ $LEASES4_AT0_ADDRESS ]; then
        log "Committed lease4 ${LEASES4_AT0_ADDRESS} for ${LEASES4_AT0_HOSTNAME}"
        add_lease4 $LEASES4_AT0_HOSTNAME $LEASES4_AT0_ADDRESS
    elif [ $LEASE4_ADDRESS ]; then
        log "Committed lease4 ${LEASE4_ADDRESS} for ${LEASE4_HOSTNAME}"
        add_lease4 $LEASE4_HOSTNAME $LEASE4_ADDRESS
    fi

    if [ $DELETED_LEASES4_SIZE -gt 0 ]; then
        MAX_LEASES=$((${DELETED_LEASES4_SIZE} - 1))
        SEQ=$(seq 0 $MAX_LEASES)
        for i in $SEQ; do
            DELETED_LEASE4_HOSTNAME=$(eval echo "\$DELETED_LEASES4_AT${i}_HOSTNAME")
            DELETED_LEASE4_ADDRESS=$(eval echo "\$DELETED_LEASES4_AT${i}_ADDRESS")
            log "Deleted lease4 ${DELETED_LEASE4_ADDRESS} for ${DELETED_LEASE4_HOSTNAME}"
            del_lease4 $DELETED_LEASE4_HOSTNAME $DELETED_LEASE4_ADDRESS
        done
    elif [ $DELETED_LEASES4_AT0_ADDRESS ]; then
        log "Deleted lease4 ${DELETED_LEASES4_AT0_ADDRESS} for ${DELETED_LEASES4_AT0_HOSTNAME}"
        del_lease4 $DELETED_LEASES4_AT0_HOSTNAME $DELETED_LEASES4_AT0_ADDRESS
    elif [ $DELETED_LEASE4_ADDRESS ]; then
        log "Deleted lease4 ${DELETED_LEASE4_ADDRESS} for ${DELETED_LEASE4_HOSTNAME}"
        del_lease4 $DELETED_LEASE4_HOSTNAME $DELETED_LEASE4_ADDRESS
    fi

    return 0
}

# Handle kea hook point lease4_release
lease4_release () {
    log "Releasing lease4 ${LEASE4_ADDRESS} for ${LEASE4_HOSTNAME}"
    del_lease4 $LEASE4_HOSTNAME $LEASE4_ADDRESS
    return 0 # handled by leases4_committed in case of multiple leases
}

# Handle kea hook point lease4_decline
lease4_decline () {
    return 0 # handled by leases4_committed
}

# Handle kea hook point lease6_renew
lease6_renew () {
    log "Renewing lease6 ${LEASE6_ADDRESS}, ${QUERY6_REMOTE_ADDR} for ${LEASE6_HOSTNAME}"
    add_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS $QUERY6_REMOTE_ADDR
    return 0 # handled by leases6_committed in case of multiple leases
}

# Handle kea hook point lease6_rebind
lease6_rebind () {
    log "Rebinding lease6 ${LEASE6_ADDRESS}, ${QUERY6_REMOTE_ADDR} for ${LEASE6_HOSTNAME}"
    add_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS $QUERY6_REMOTE_ADDR
    return 0 # handled by leases6_committed in case of multiple leases
}

# Handle kea hook point lease6_expire
lease6_expire () {
    log "Expiring lease6 ${LEASE6_ADDRESS}, ${QUERY6_REMOTE_ADDR} for ${LEASE6_HOSTNAME}"
    del_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS $QUERY6_REMOTE_ADDR
    return 0 # handled by leases6_committed in case of multiple leases
}

# Handle kea hook point lease6_recover
lease6_recover () {
    log "Recovering lease6 ${LEASE6_ADDRESS}, ${QUERY6_REMOTE_ADDR} for ${LEASE6_HOSTNAME}"
    add_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS $QUERY6_REMOTE_ADDR
    return 0 # handled by leases6_committed in case of multiple leases
}

# Handle kea hook point leases6_committed
leases6_committed () {
    if [ $LEASES6_SIZE -gt 0 ]; then
        MAX_LEASES=$((${LEASES6_SIZE} - 1))
        SEQ=$(seq 0 $MAX_LEASES)
        for i in $SEQ; do
            LEASE6_ADDRESS=$(eval echo "\$LEASES6_AT${i}_ADDRESS")
            LEASE6_HOSTNAME=$(eval echo "\$LEASES6_AT${i}_HOSTNAME")
            log "Committed lease6 ${LEASE6_ADDRESS} for ${LEASE6_HOSTNAME}"
            add_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS
        done
    elif [ $LEASES6_AT0_ADDRESS ]; then
        log "Committed lease6 ${LEASES6_AT0_ADDRESS} for ${LEASES6_AT0_HOSTNAME}"
        add_lease6 $LEASES6_AT0_HOSTNAME $LEASES6_AT0_ADDRESS
    elif [ $LEASE6_ADDRESS ]; then
        log "Committed lease6 ${LEASE6_ADDRESS} for ${LEASE6_HOSTNAME}"
        add_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS
    fi

    if [ $DELETED_LEASES6_SIZE -gt 0 ]; then
        MAX_LEASES=$((${DELETED_LEASES6_SIZE} - 1))
        SEQ=$(seq 0 $MAX_LEASES)
        for i in $SEQ; do
            DELETED_LEASE6_ADDRESS=$(eval echo "\$DELETED_LEASES6_AT${i}_ADDRESS")
            DELETED_LEASE6_HOSTNAME=$(eval echo "\$DELETED_LEASES6_AT${i}_HOSTNAME")
            log "Deleted lease6 ${DELETED_LEASE6_ADDRESS} for ${DELETED_LEASE6_HOSTNAME}"
            del_lease6 $DELETED_LEASE6_HOSTNAME $DELETED_LEASE6_ADDRESS
        done
    elif [ $DELETED_LEASES6_AT0_ADDRESS ]; then
        log "Deleted lease6 ${DELETED_LEASES6_AT0_ADDRESS} for ${DELETED_LEASE6_AT0_HOSTNAME}"
        del_lease6 $DELETED_LEASE6_AT0_HOSTNAME $DELETED_LEASES6_AT0_ADDRESS
    elif [ $DELETED_LEASE6_ADDRESS ]; then
        log "Deleted lease6 ${DELETED_LEASE6_ADDRESS} for ${DELETED_LEASE6_HOSTNAME}"
        del_lease6 $DELETED_LEASE6_HOSTNAME $DELETED_LEASE6_ADDRESS
    fi

    return 0
}

# Handle kea hook point lease6_release
lease6_release () {
    log "Releasing lease6 ${LEASE6_ADDRESS}, ${QUERY6_REMOTE_ADDR} for ${LEASE6_HOSTNAME}"
    del_lease6 $LEASE6_HOSTNAME $LEASE6_ADDRESS $QUERY6_REMOTE_ADDR
    return 0 # handled by leases6_committed in case of multiple leases
}

# Handle kea hook point lease6_decline
lease6_decline () {
    return 0 # handled by leases6_committed
}

# Handle function calls
case "$1" in
    "lease4_renew")
        lease4_renew
        ;;
    "lease4_expire")
        lease4_expire
        ;;
    "lease4_recover")
        lease4_recover
        ;;
    "leases4_committed")
        leases4_committed
        ;;
    "lease4_release")
        lease4_release
        ;;
    "lease4_decline")
        lease4_decline
        ;;
    "lease6_renew")
        lease6_renew
        ;;
    "lease6_rebind")
        lease6_rebind
        ;;
    "lease6_expire")
        lease6_expire
        ;;
    "lease6_recover")
        lease6_recover
        ;;
    "leases6_committed")
        leases6_committed
        ;;
    "lease6_release")
        lease6_release
        ;;
    "lease6_decline")
        lease6_decline
        ;;
    "-h"|"--help")
        echo "$HELP"
        exit 0
        ;;
    "-v"|"--version")
        echo "$PROGNAME 0.1"
        exit 0
        ;;
    *)
        unknown_handle "${@}"
        ;;
esac
