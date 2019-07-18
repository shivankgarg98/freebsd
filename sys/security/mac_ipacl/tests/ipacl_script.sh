#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019 Shivank Garg <shivank@FreeBSD.org>
# Copyright (c) 2019 Bjoern A. Zeeb <bz@FreeBSD.org>
# 
# All rights reserved.
# This code was developed as a Google Summer of Code 2019 project
# under the guidance of Mr. Bjoern A. Zeeb.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

#!/bin/sh
# $FreeBSD$

sysctl security.mac.ipacl >/dev/null 2>&1
if [ $? -ne 0 ]; then
        echo "1..0 # SKIP MAC_IPACL is unavailable."
        exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "1..0 # SKIP testcases must be run as root"
	exit 0
fi

ntest=1

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
