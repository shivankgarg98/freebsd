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
			if [ "${jid}" -eq 0 ]; then
				echo | ifconfig ${interface} ${address}/${prefix} up
				RetVal=$?
			else
				echo | jexec ${jid} ifconfig ${interface} ${address}/${prefix} up
				RetVal=$?
	                fi
	elif [ "${proto}" = "ipv6" ]; then
			if [ "${jid}" -eq 0 ]; then
				echo | ifconfig ${interface} inet6 ${address} prefixlen ${prefix}
				RetVal=$?
	                else
				echo | jexec ${jid} ifconfig ${interface} inet6 ${address} prefixlen ${prefix}
				RetVal=$?
	                fi
	fi
	if [ ${RetVal} -eq 0 ]; then
		echo ok
	else
		echo fl
	fi

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
                echo "ok : PASS ${ntest}"
        elif [ "${out}" = "ok" ] || [ "${out}" = "fl" ]; then
                echo "not ok : FAIL ${ntest} # '${out}' != '${expect_with_rule}'"
        else
                echo "not ok :  FAIL ${ntest} # unexpected output: '${out}'"
        fi
        : $(( ntest += 1 ))
}
