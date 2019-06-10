#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: testcases must be run as root"
	exit 0
fi

ntest=1

echo "ipacl_script.sh"

test_ip() {
	local proto interface address prefix jid

	proto=${1}
	interface=${2}
	address=${3}
	prefix=${4}
	jid=${5} #if jid = 0 then assume host

	if [ "${proto}" = "ipv4" ]; then
			if [ "${jid}" = "0" ]; then
		        out=$(
		        echo | ifconfig ${interface} ${address}/${prefix} up
		        wait
		        )
	                else
		        out=$(
		        echo | jexec ${jid} ifconfig ${interface} ${address}/${prefix} up
		        wait
		        )
	                fi
	elif [ "${proto}" = "ipv6" ]; then
			if [ "${jid}" = "0" ]; then
		        out=$(
		        echo | ifconfig ${interface} inet6 ${address} prefixlen ${prefix}
		        wait
		        )
	                else
		        out=$(
		        echo | jexec ${jid} ifconfig ${interface} inet6 ${address} prefixlen ${prefix}
		        wait
		        )
	                fi
	fi
	
	case "${out}" in
		"SIOCAIFADDR" | "TODO-update error")
			echo fl
			;;
		"mac_inet*" | "	*")
			echo ok
			;;
		*)
			echo "${out}"
			;;
	esac
}

exec_test() {
	local expect_with_rule proto interface address prefix jid
	expect_with_rule=${1}
	proto=${2}
	interface=${3}
	address=${4}
	prefix=${5}
	jid=${6}

	out=$(test_ip "${proto}" "${interface}" "${address}" "${prefix}" "${jid}")
        if [ "${out}" = "${expect_with_rule}" ]; then
                echo "ok ${ntest}"
        elif [ "${out}" = "ok" ] || [ "${out}" = "fl" ]; then
                echo "not ok ${ntest} # '${out}' != '${expect_with_rule}'"
        else
                echo "not ok ${ntest} # unexpected output: '${out}'"
        fi
        : $(( ntest += 1 ))
}
