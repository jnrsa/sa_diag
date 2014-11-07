#!/bin/bash

# Security Analytics diagnostic script

# Init a lot of vars for sanity
SA_APPLIANCE_HW=""
SA_APPLIANCE_TYPE=""
SA_APPLIANCE_BROKER_EXISTS=0
SA_APPLIANCE_JETTY_EXISTS=0
SA_APPLIANCE_RE_EXISTS=0
SA_BOOT_KERN_VER=0
SA_CURRENT_KERN_VER=0
SA_DIAG_VER="0.9.9.3"
SA_FREE_MEM_INT=0
SA_INITRRAMFS_IMG=0
SA_JUST_RUN=0
SA_RELEASE_VER="10"
SA_RUN_IN_VM=0
SA_STOR_RAID_COUNT_LSPCI=0
SA_STOR_RAID_COUNT_MEGA=0
SA_STOR_RAID_COUNTER=0
SA_STOR_RAID_RAM_ERRS_COR=0
SA_STOR_RAID_RAM_ERRS_UNCOR=0
SA_SWAP_USED=0
SA_ULIMIT_CONF=1
SA_ULIMIT_ENV=0

# A prettyprinting decl for some output -
# Raises cursor one line, returns to first column,
# erases to EOL, returns to first column
erase_newline () {
	echo -en "\033[1A\r\033[K\r"
}

die () {
	echo -e "$*"
	exit 1
}

live () {
	echo -e "$*"
	exit 0
}

# Extend the existing PATH for MegaCLI
PATH="${PATH}:/opt/MegaRAID/MegaCli"

# Test for dependencies
# for i in MegaCli64 dmidecode lspci ntpq rpm ; do
for i in dmidecode ip6tables iptables lspci ntpq rpm ; do	
	which ${i} &> /dev/null || die "${i} not available. Cannot continue.\n"
done

# Set the path to MegaCLI64 so we can change it later
SA_RAID_UTIL="/opt/MegaRAID/MegaCli/MegaCli64"

# Generic error printer; takes (and prints) a warning type
# and a warning message; highlights the type red/bold when
# printing
sa_print_err () {
	case $1 in
		0 ) echo -e "[\033[1;31mCritical\033[0m] $2" ;;
		1 ) echo -e "[\033[1;31mError\033[0m] $2" ;;
		2 ) echo -e "[\033[1;33mWarning\033[0m] $2" ;;
		3 ) echo -e "[\033[1;34mInfo\033[0m] $2" ;;
		* ) die "Internal logic error.\n" ;;
	esac
}

# Print usage info
sa_help () {
	echo -e "Usage: `basename $0` [OPTION]..."
	echo -e "Generic diagnostics utility for Security Analytics appliances."
	echo
	echo -e "\t-f\t\tforces execution, bypassing hardware check"
	echo -e "\t-h\t\tprint this help and exit"
	echo -e "\t-v\t\tprint the script version and exit"
	echo -e "\t-V\t\tattempt to run in a VM"
	echo
	exit 0
}

# Verify that we have at least one NTP peer
sa_test_ntp () {
	# We need at least one synchronization peer, denoted by a *
	SA_NTP_PEER_NUM=$( ntpq -np 2> /dev/null | grep '^*' | wc -l )
	if [ "${SA_NTP_PEER_NUM}" -lt 1 ] ; then
		sa_print_err 2 "Your system time is not synchronized by NTP."
		if [ ! -f /etc/ntp.conf ] ; then
			sa_print_err 2 "The NTP configuration file (/etc/ntp.conf) does not exist."
		else
			grep ^server /etc/ntp.conf &> /dev/null
			if [ $? -ne 0 ] ; then
				sa_print_err 2 "There are no peers defined in /etc/ntp.conf."
			fi
		fi
	fi
}

# Only works on R5x0 and R6x0 appliances at this time
SA_APPLIANCE_HW=$( dmidecode -s system-product-name | grep ^Power 2> /dev/null | awk '{print $2}' )

# Also grab the service tag
SA_APPLIANCE_SN=$( dmidecode -s system-serial-number )

# Figure out what kind of appliance this is supposed to be
# based on installed packages
sa_get_appliance_type () {
	# Create temp file for an RPM list extract
	SA_APP_TYPE_TEMP=`mktemp` || die "Could not create temporary file.\n"
	rpm -qa | egrep '(^nw|jetty|^rsa|^re-server)' &> "${SA_APP_TYPE_TEMP}"

	# Get the (apparent) installed SA version
	grep ^nw "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -ne 0 ] ; then
		grep ^rsa "${SA_APP_TYPE_TEMP}" &> /dev/null
		if [ $? -ne 0 ] ; then
			rm -f "${SA_NETFILTER_TEMP}"
			die "Is this a Security Analytics appliance?\n"
		else
			SA_RELEASE_VER=$( grep '^rsa.*server' "${SA_APP_TYPE_TEMP}" | awk -F- '{print $4}' | sort -n -r | head -n 1 )
		fi
	fi
	SA_RELEASE_VER=$( grep '^nw.*-10\.' "${SA_APP_TYPE_TEMP}" | awk -F- '{print $2}' | sort -n -r | head -n 1)
	if [ -z "${SA_RELEASE_VER}" ] ; then
		rm -f "${SA_NETFILTER_TEMP}"
		die "Is this a Security Analytics appliance?\n"
	fi
	rm -f "${SA_NETFILTER_TEMP}"

	# Check for the Reporting Engine
	grep re-server "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_RE_EXISTS=1
	fi

	# Check for Jetty
	grep jetty "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_JETTY_EXISTS=1
	fi

	# Check for Broker service
	grep broker "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_BROKER_EXISTS=1
	fi

	# AIO, SA Server, and Broker types
	if [[ ${SA_APPLIANCE_JETTY_EXISTS} -eq 1 && ${SA_APPLIANCE_RE_EXISTS} -eq 1 ]] ; then
		grep concentrator "${SA_APP_TYPE_TEMP}" &> /dev/null
		if [ $? -eq 0 ] ; then
			SA_APPLIANCE_TYPE=SA_AIO ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		elif [ ${SA_APPLIANCE_BROKER_EXISTS} -eq 1 ] ; then
			SA_APPLIANCE_TYPE=SA_SERVER ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		elif [ $? -ne 0 ] ; then
			SA_APPLIANCE_TYPE=SA_SERVER_NO_BROKER ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		fi
	elif [[ ${SA_APPLIANCE_JETTY_EXISTS} -eq 1 && ${SA_APPLIANCE_RE_EXISTS} -eq 0 ]] ; then
		grep broker "${SA_APP_TYPE_TEMP}" &> /dev/null
		if [ $? -eq 0 ] ; then
			SA_APPLIANCE_TYPE=SA_SERVER_NO_RE ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		else
			SA_APPLIANCE_TYPE=SA_SERVER_NO_BROKER_NO_RE ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		fi
	fi
	if [ ${SA_APPLIANCE_BROKER_EXISTS} -eq 1 ] ; then
		SA_APPLIANCE_TYPE=SA_BROKER ; rm "${SA_APP_TYPE_TEMP}" ; return 0
	fi

	# Log decoder types 
	grep logdecoder "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		grep concentrator "${SA_APP_TYPE_TEMP}" &> /dev/null
		if [ $? -eq 0 ] ; then
			SA_APPLIANCE_TYPE=SA_LOG_HYBRID ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		else
			SA_APPLIANCE_TYPE=SA_LOG_DECODER ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		fi
	fi
	# We now sell log-collector-only appliances
	grep logcollector "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_TYPE=SA_LOG_COLLECTOR ; rm "${SA_APP_TYPE_TEMP}" ; return 0
	fi

	# Packet decoder types
	grep nwdecoder "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		grep concentrator "${SA_APP_TYPE_TEMP}" &> /dev/null
		if [ $? -eq 0 ] ; then
			SA_APPLIANCE_TYPE=SA_PACKET_HYBRID ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		else
			SA_APPLIANCE_TYPE=SA_PACKET_DECODER ; rm "${SA_APP_TYPE_TEMP}" ; return 0
		fi
	fi

	# Concentrator
	grep concentrator "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_TYPE=SA_CONCENTRATOR ; rm "${SA_APP_TYPE_TEMP}" ; return 0
	fi

	# ESA type
	grep rsa-esa-server "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_TYPE=SA_ESA ; rm "${SA_APP_TYPE_TEMP}" ; return 0
	fi

	# Stand-alone Malware analysis
	grep 'rsaMalwareDevice-' "${SA_APP_TYPE_TEMP}" &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_APPLIANCE_TYPE=SA_MALWARE ; rm "${SA_APP_TYPE_TEMP}" ; return 0
	fi

	# Finally, clean up the temp file, in case
	rm "${SA_APP_TYPE_TEMP}"
	die "Failed to determine appliance type.\n"
}

sa_test_firewall_port () {
	grep -E "${1}" "${SA_NETFILTER_TEMP}" &> /dev/null
	if [ $? -ne 0 ] ; then
		SA_FIREWALL_PORT_NUM=$( echo "${1}" | sed 's/[[:punct:]]//g' | sed 's/\(^[a-z][a-z][a-z]\)\([0-9]\)/\1 \2/g' )
		sa_print_err 1 "${2} service ${3} port (${SA_FIREWALL_PORT_NUM}) is not open in host-based firewall."
	fi
}

sa_test_firewall () {
	# Create temp file for netfilter rules list
	SA_NETFILTER_TEMP=`mktemp` || die "Could not create temporary file.\n"

	# If there are no ACCEPT rules in netfilter's tables
	iptables -n -L INPUT 2> /dev/null | grep ^ACCEPT > "${SA_NETFILTER_TEMP}"
	ip6tables -n -L INPUT 2> /dev/null | grep ^ACCEPT >> "${SA_NETFILTER_TEMP}"
	if [ $? -ne 0 ] ; then
		sa_print_err 1 "Host-based firewall rules are preventing all network access."
		rm -f "${SA_NETFILTER_TEMP}"
	fi

	# If the default policies are wrong
	iptables -n -L | grep -E '(INPUT|OUTPUT).*policy REJECT' &> /dev/null
	if [ $? -eq 0 ] ; then
		sa_print_err 1 "Default netfilter policies are wrong."
	fi

	# FIXME: More testing of the actual firewall rules

	# echo "DEBUG:"
	# cat "${SA_NETFILTER_TEMP}"

	# Always need ssh port
	sa_test_firewall_port 'tcp.*[\ ,\:]22' ssh ""

	# Appliance service always exists?
	case ${SA_RELEASE_VER} in
		10.3.* )	sa_test_firewall_port 'tcp.*50006' Appliance native
					sa_test_firewall_port 'tcp.*50106' Appliance REST
					;;
		10.4.* )	sa_test_firewall_port 'tcp.*56006' Appliance native
					sa_test_firewall_port 'tcp.*50106' Appliance REST
					;;
		* ) 		sa_print_err 2 "Internal script error."
					;;
	esac

	expr match "${SA_APPLIANCE_TYPE}" "SA_SERVER" &> /dev/null
	if [ $? -eq 0 ] ; then
		sa_test_firewall_port 'tcp.*80' yum-http ""
		case ${SA_RELEASE_VER} in
			10.3.* )	sa_test_firewall_port 'tcp.*\:80' yum-http ""
						;;
			10.4.* )	sa_test_firewall_port 'tcp.* 80' yum-http ""
						sa_test_firewall_port 'tcp.*8140' Puppet ""
						;;
		esac
	fi

	# Always needed on 10.4?
	case ${SA_RELEASE_VER} in
		10.4.* )	sa_test_firewall_port 'tcp.*5671' RabbitMQ ""
					# sa_test_firewall_port 'tcp.*61614' STOMP ""
					;;
	esac

	# Check to see if snmpd is running
	pgrep snmpd &> /dev/null
	if [ $? -eq 0 ] ; then
		sa_test_firewall_port 'udp.*161' SNMP ""
	fi

	case ${SA_RELEASE_VER} in
		10.3.* )
			case ${SA_APPLIANCE_TYPE} in
				SA_PACKET_HYBRID )	sa_test_firewall_port 'tcp.*50004' "Packet decoder" native
									sa_test_firewall_port 'tcp.*50104' "Packet decoder" REST
									sa_test_firewall_port 'tcp.*50005' "Concentrator" native
									sa_test_firewall_port 'tcp.*50105' "Concentrator" REST
									;;
				SA_PACKET_DECODER )	sa_test_firewall_port 'tcp.*50004' "Packet decoder" native
									sa_test_firewall_port 'tcp.*50104' "Packet decoder" REST
									;;
				SA_LOG_DECODER )	sa_test_firewall_port 'tcp.*50001' "Log collector" native
								 	sa_test_firewall_port 'tcp.*50101' "Log collector" REST
									sa_test_firewall_port 'tcp.*50002' "Log decoder" native
									sa_test_firewall_port 'tcp.*50102' "Log decoder" REST
									;;
				SA_LOG_HYBRID )		sa_test_firewall_port 'tcp.*50001' "Log collector" native
								 	sa_test_firewall_port 'tcp.*50101' "Log collector" REST
									sa_test_firewall_port 'tcp.*50002' "Log decoder" native
									sa_test_firewall_port 'tcp.*50102' "Log decoder" REST
									sa_test_firewall_port 'tcp.*50005' "Concentrator" native
									sa_test_firewall_port 'tcp.*50105' "Concentrator" REST
									sa_test_firewall_port 'tcp.*6514' "Syslog (SSL)" ""
									sa_test_firewall_port 'tcp.*514' "Syslog (tcp)" ""
									sa_test_firewall_port 'udp.*514' "Syslog (udp)" ""
									;;
				SA_LOG_COLLECTOR ) 	sa_test_firewall_port 'tcp.*50001' "Log collector" native
								 	sa_test_firewall_port 'tcp.*50101' "Log collector" REST
									;;
				SA_MALWARE ) 		sa_test_firewall_port 'tcp.*60007' "Malware" native
									;;
				SA_SERVER )			sa_test_firewall_port 'tcp.*443' "SA UI (Jetty)" ""
									sa_test_firewall_port 'tcp.*50003' "Broker" native
									sa_test_firewall_port 'tcp.*50103' "Broker" REST
									sa_test_firewall_port 'tcp.*50010' "CAS" REST
									# sa_test_firewall_port 'tcp.*50009' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*56025' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
									;;
				SA_SERVER_NO_BROKER )	sa_test_firewall_port 'tcp.*443' "SA UI (Jetty)" ""
										sa_test_firewall_port 'tcp.*50010' "CAS" REST
										# sa_test_firewall_port 'tcp.*50009' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*56025' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
										;;
				SA_CONCENTRATOR )	sa_test_firewall_port 'tcp.*50005' "Concentrator" native
									sa_test_firewall_port 'tcp.*50105' "Concentrator" REST
									;;
			esac
			;;
		10.4.* )
			case ${SA_APPLIANCE_TYPE} in
				SA_PACKET_HYBRID )	sa_test_firewall_port 'tcp.*56004' "Packet decoder" native
									sa_test_firewall_port 'tcp.*50104' "Packet decoder" REST
									sa_test_firewall_port 'tcp.*56005' "Concentrator" native
									sa_test_firewall_port 'tcp.*50105' "Concentrator" REST
									;;
				SA_PACKET_DECODER )	sa_test_firewall_port 'tcp.*56004' "Packet decoder" native
									sa_test_firewall_port 'tcp.*50104' "Packet decoder" REST
									;;
				SA_LOG_DECODER )	sa_test_firewall_port 'tcp.*56001' "Log collector" native
								 	sa_test_firewall_port 'tcp.*50101' "Log collector" REST
									sa_test_firewall_port 'tcp.*56002' "Log decoder" native
									sa_test_firewall_port 'tcp.*50102' "Log decoder" REST
									;;
				SA_LOG_HYBRID )		sa_test_firewall_port 'tcp.*56001' "Log collector" native
								 	sa_test_firewall_port 'tcp.*50101' "Log collector" REST
									sa_test_firewall_port 'tcp.*56002' "Log decoder" native
									sa_test_firewall_port 'tcp.*50102' "Log decoder" REST
									sa_test_firewall_port 'tcp.*56005' "Concentrator" native
									sa_test_firewall_port 'tcp.*50105' "Concentrator" REST
									sa_test_firewall_port 'tcp.*6514' "Syslog (SSL)" ""
									sa_test_firewall_port 'tcp.*514' "Syslog (tcp)" ""
									sa_test_firewall_port 'udp.*514' "Syslog (udp)" ""
									;;
				SA_LOG_COLLECTOR ) 	sa_test_firewall_port 'tcp.*56001' "Log collector" native
								 	sa_test_firewall_port 'tcp.*50101' "Log collector" REST
									;;
				SA_MALWARE ) 		sa_test_firewall_port 'tcp.*60007' "Malware" native
									;;
				SA_SERVER )			sa_test_firewall_port 'tcp.*443' "SA UI (Jetty)" ""
									sa_test_firewall_port 'tcp.*56003' "Broker" native
									sa_test_firewall_port 'tcp.*50103' "Broker" REST
									# sa_test_firewall_port 'tcp.*50010' "CAS"
									# sa_test_firewall_port 'tcp.*50009' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*56025' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
									;;
				SA_SERVER_NO_BROKER )	sa_test_firewall_port 'tcp.*443' "SA UI (Jetty)" ""
										# sa_test_firewall_port 'tcp.*50010' "CAS"
										# sa_test_firewall_port 'tcp.*50009' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*56025' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
										;;
				SA_CONCENTRATOR )	sa_test_firewall_port 'tcp.*56005' "Concentrator" native
									sa_test_firewall_port 'tcp.*50105' "Concentrator" REST
									;;
			esac
			;;
		* )	sa_print_err 2 "Internal script error."
			;;
	esac
	# case ${SA_APPLIANCE_TYPE} in
	#	SA_PACKET_HYBRID )

	rm -f "${SA_NETFILTER_TEMP}"
}

sa_test_gro () {
	for SA_NET_IFACE in $( ls /etc/sysconfig/network-scripts/ifcfg-* | grep -v ifcfg-lo | sed 's/^\/.*\/ifcfg-//g' ) ; do
		ethtool -k "${SA_NET_IFACE}" &> /dev/null
		if [ $? -ne 0 ] ; then
			sa_print_err 1 "Could not retrieve features for interface ${SA_NET_IFACE}."
			return 1
		fi
		ethtool -k "${SA_NET_IFACE}" | grep 'generic-receive-offload: on' &> /dev/null && sa_print_err 2 "GRO is enabled on ${SA_NET_IFACE}."
	done
}

# Try to guess latest kernel RPM. Experimental!
sa_test_kernel_ver () {
	# Get latest kernel installed
	local BOOT_KERN_VER_MAJOR=$( rpm -qi kernel | grep Version | awk -F: '{print $2}' | awk '{print $1}' | tail -n 1 )
	local BOOT_KERN_VER_MINOR=$( rpm -qi kernel | grep Release | awk -F: '{print $2}' | awk '{print $1}' | tail -n 1 )
	SA_BOOT_KERN_VER="${BOOT_KERN_VER_MAJOR}-${BOOT_KERN_VER_MINOR}"
	uname -r | grep x86_64 &> /dev/null
	if [ $? -eq 0 ] ; then
		SA_BOOT_KERN_VER="${SA_BOOT_KERN_VER}.x86_64"
	else
		SA_BOOT_KERN_VER="${SA_BOOT_KERN_VER}.i686"
	fi

	# Get default kernel from bootloader
	SA_CURRENT_KERN_VER=$( grubby --default-kernel 2> /dev/null | sed 's/^\/boot\/[vmlinuz-]*//' )
	if [ ${#SA_CURRENT_KERN_VER} -eq 0 ] ; then sa_print_err 1 "Could not retrieve current default kernel!" ; fi

	# Compare...
	if [ "${SA_CURRENT_KERN_VER}" != "${SA_BOOT_KERN_VER}" ] ; then
		sa_print_err 1 "Bootloader kernel doesn't match latest installed. May be outdated."
	fi
}

sa_test_anaconda () {
	# Does /etc/grub.conf exist?
	if [ ! -L /etc/grub.conf ] ; then
		sa_print_err 1 "/etc/grub.conf is not a symlink. You will experience problems upgrading kernels."
	elif [ ! -h /etc/grub.conf ] ; then
		sa_print_err 1 "/etc/grub.conf does not exist. You will experience problems upgrading kernels."
	# Does the link point where it should?
	elif [ -h /etc/grub.conf ] ; then
		if [[ ! $( ls -l /etc/grub.conf | awk '{print $11}' ) =~ .*\/boot\/grub\/grub\.conf.* ]] ; then
			sa_print_err 2 "/etc/grub.conf is invalid. You will experience problems upgrading kernels."
		fi
	fi

	# Does /etc/sysconfig/kernel exist?
	if [ ! -f /etc/sysconfig/kernel ] ; then
		sa_print_err 1 "/etc/sysconfig/kernel does not exist. You will experience problems upgrading kernels."
	# But is it valid?
	elif [ -f /etc/sysconfig/kernel ] ; then
		grep '^UPDATEDEFAULT=yes$' /etc/sysconfig/kernel &> /dev/null || sa_print_err 2 "/etc/sysconfig/kernel does not appear valid."
		grep '^DEFAULTKERNEL=kernel$' /etc/sysconfig/kernel &> /dev/null || die sa_print_err 2 "/etc/sysconfig/kernel does not appear valid."
	fi
}

sa_test_sys_ram () {
	# bc is not distributed with SA, so get a result from Python...
	# SA_FREE_MEM=$( python -c "print '%(#).2f' % {\"#\": $( free -m | grep -E '^-' | awk '{print $4}' ).0/$( free -m | grep -E '^Mem' | awk '{print $2}' ).0}" )
	SA_FREE_MEM_INT=$( python -c "print '%(#)d' % {\"#\": $( free -m | grep -E '^-' | awk '{print $4}' ).0/$( free -m | grep -E '^Mem' | awk '{print $2}' ).0*100}" )

	if [ ${SA_FREE_MEM_INT} -lt 10 ] ; then
		sa_print_err 2 "Free memory is only ${SA_FREE_MEM_INT}%."
	fi

	SA_SWAP_USED=$( free -m | grep -E '^Swap' | awk '{print $3}' )

	if [ "${SA_SWAP_USED}" -ne 0 ] ; then
		sa_print_err 2 "System has started swapping to disk."
	fi
}

sa_test_sys_tmp () {
	if [ $( ls -dl /tmp | awk '{print $1}' | awk '{print $1}') != "drwxrwxrwt." ] ; then
		sa_print_err 1 "Permissions on /tmp are incorrect."
	fi
}

sa_test_raid_health () {
	SA_STOR_RAID_COUNT_LSPCI=$( lspci | grep "RAID bus" | wc -l )
	SA_STOR_RAID_COUNT_MEGA=$( /opt/MegaRAID/MegaCli/MegaCli64 -adpcount -NoLog | grep '^Controller Count' | awk '{print $3}' | tr -d '[:punct:]' )

	if [ "${SA_STOR_RAID_COUNT_MEGA}" -ne "${SA_STOR_RAID_COUNT_LSPCI}" ] ; then
		sa_print_err 0 "PCI bus and MegaRAID adapter count mismatch!"
	fi

	# Run a heck of a lot of tests
	while [ ${SA_STOR_RAID_COUNTER} -lt 2 ] ; do
		# Create temp file for MegaCLI output
		SA_MEGACLI_TEMP=`mktemp` || die "Could not create temporary file.\n"
		# Fill the file with MegaCLI output
		"${SA_RAID_UTIL}" -adpallinfo "-a${SA_STOR_RAID_COUNTER}" -NoLog &> "${SA_MEGACLI_TEMP}"
		"${SA_RAID_UTIL}" -LdPdInfo "-a${SA_STOR_RAID_COUNTER}" -NoLog &>> "${SA_MEGACLI_TEMP}"
		"${SA_RAID_UTIL}" -pdlist "-a${SA_STOR_RAID_COUNTER}" -NoLog &>> "${SA_MEGACLI_TEMP}"
		"${SA_RAID_UTIL}" -encinfo "-a${SA_STOR_RAID_COUNTER}" -NoLog &>> "${SA_MEGACLI_TEMP}"

		# Look for enclosure problems
		grep 'controller is not present' "${SA_MEGACLI_TEMP}" &> /dev/null
		if [ $? -eq 0 ] ; then
			rm -f "${SA_MEGACLI_TEMP}" &> /dev/null || die "Could not unlink temp file.\n"
			sa_print_err 0 "Failed to retrieve status for an enclosure on adapter ${SA_STOR_RAID_COUNTER}!" ; return 255
		fi
		# Retrieve "ECC Bucket Count"
		if [ $( grep ^ECC "${SA_MEGACLI_TEMP}" | awk '{print $5}') -ne 0 ] ; then
			sa_print_err 1 "Failing RAID adapter ${SA_STOR_RAID_COUNTER} has non-zero ECC count."
		fi
		# Retrieve "ROC" and controller temperatures
		SA_STOR_RAID_CON_TEMP=$( grep temperature "${SA_MEGACLI_TEMP}" | tail -n 1 | awk '{print $4}' )
		SA_STOR_RAID_ROC_TEMP=$( grep temperature "${SA_MEGACLI_TEMP}" | head -n 1 | awk '{print $4}' )
		if [[ ${SA_STOR_RAID_CON_TEMP} -gt 72 || ${SA_STOR_RAID_ROC_TEMP} -gt 60 ]] ; then
			sa_print_err 2 "RAID controller ${SA_STOR_RAID_COUNTER} is over-temperature: ${SA_STOR_RAID_CON_TEMP}C, ${SA_STOR_RAID_ROC_TEMP}C."
		# Again, with a higher limit and a more dire warning
		elif [[ ${SA_STOR_RAID_CON_TEMP} -gt 81 || ${SA_STOR_RAID_ROC_TEMP} -gt 70 ]] ; then
			sa_print_err 1 "RAID controller ${SA_STOR_RAID_COUNTER} is over-temperature! ${SA_STOR_RAID_CON_TEMP}C, ${SA_STOR_RAID_ROC_TEMP}C"
		# For the historical record
		elif [[ ${SA_STOR_RAID_CON_TEMP} -eq 0 || ${SA_STOR_RAID_ROC_TEMP} -eq 0 ]] ; then
			sa_print_err 3 "RAID controller does not support temperature sensor."
		else
			sa_print_err 3 "RAID controller temperatures: ${SA_STOR_RAID_CON_TEMP}C, ${SA_STOR_RAID_ROC_TEMP}C"
		fi
		# Look for controller scratch RAM errors
		SA_STOR_RAID_RAM_ERRS_COR=$( grep '^Memory Cor' "${SA_MEGACLI_TEMP}" | awk '{print $5}' )
		SA_STOR_RAID_RAM_ERRS_UNCOR=$( grep '^Memory Unc' "${SA_MEGACLI_TEMP}" | awk '{print $5}' )
		if [[ ${SA_STOR_RAID_RAM_ERRS_COR} -ne 0 || ${SA_STOR_RAID_RAM_ERRS_UNCOR} -ne 0 ]] ; then
			sa_print_err 1 "Failing RAID adapter ${SA_STOR_RAID_COUNTER} has scratch RAM errors."
		fi
		# Look for controller virtual disk problems
		if [[ $( grep -E '^[[:space:]]*Degr' "${SA_MEGACLI_TEMP}" | awk '{print $3}' ) -ne 0 || $( grep -E '^[[:space:]]*Offl' "${SA_MEGACLI_TEMP}" | awk '{print $3}' ) -ne 0 ]] ; then
			sa_print_err 1 "One or more virtual disks offline or degraded on adapter ${SA_STOR_RAID_COUNTER}."
		fi
		# Look for controller physical disk problems
		if [ "${SA_APPLIANCE_HW}" != "R510" ] ; then
			if [[ $( grep -E '^[[:space:]]*Critical' "${SA_MEGACLI_TEMP}" | awk '{print $4}' ) -ne 0 || $( grep -E '^[[:space:]]*Failed' "${SA_MEGACLI_TEMP}" | awk '{print $4}' ) -ne 0 ]] ; then
				sa_print_err 1 "One or more physical disks critical or failed on adapter ${SA_STOR_RAID_COUNTER}."
			fi
		fi
		# Look for foreign disks
		grep '^Foreign State' "${SA_MEGACLI_TEMP}" | grep -v ': None' &> /dev/null
		if [ $? -eq 0 ] ; then
			sa_print_err 2 "One or more disks in a foreign state on adapter ${SA_STOR_RAID_COUNTER}."
		fi
		# Look for bad blocks
		grep '^Bad Blocks' "${SA_MEGACLI_TEMP}" | grep -v 'No$' &> /dev/null
		if [ $? -eq 0 ] ; then
			sa_print_err 1 "One or more bad blocks detected on adapter ${SA_STOR_RAID_COUNTER}."
		fi
		# Look for SMART errors
		grep alert "${SA_MEGACLI_TEMP}" | grep -v 'No$' &> /dev/null
		if [ $? -eq 0 ] ; then
			sa_print_err 1 "One or more SMART errors detected on adapter ${SA_STOR_RAID_COUNTER}."
		fi
		let "SA_STOR_RAID_COUNTER += 1"
		rm -f "${SA_MEGACLI_TEMP}" &> /dev/null || die "Could not unlink temp file.\n"
	done
}

sa_test_corefiles () {
	grep -rv '^#' /etc/security/limit* 2> /dev/null | grep core &> /dev/null
	SA_ULIMIT_CONF=$?
	SA_ULIMIT_ENV=$( ulimit -c )
	if [[ ${SA_ULIMIT_CONF} -ne 0 && "${SA_ULIMIT_ENV}" == "0" ]] ; then
		sa_print_err 3 "Core dumps are disabled. Not looking for any."
	else
		if [ $( find / -name "core.[0-9][0-9]*" | wc -l ) -ne 0 ] ; then
			sa_print_err 1 "Found some core files."
		fi
	fi
}

sa_test_service () {
	# Get the PID first
	SA_SERVICE_PID=$( pgrep -f "${1}" 2> /dev/null )
	# Quick, strip punctuation for the Malware service case
	SA_SERVICE_NAME=$( echo "${1}" | sed 's/[[:punct:]]//g' )
	# If there is no PID, then it's not running. Exit.
	if [ ${#SA_SERVICE_PID} -eq 0 ] ; then
		sa_print_err 2 "Service ${SA_SERVICE_NAME} is not running."
		return 1
	fi
	# Create temp file for lsof output
	SA_SERVICE_TEMP=`mktemp` || die "Could not create temporary file.\n"
	# Find what ports it has bound
	lsof -Fn -P -a -i -p "${SA_SERVICE_PID}" -sTCP:LISTEN | grep -v ^p > "${SA_SERVICE_TEMP}"
	for SA_SERVICE_PORT in $( echo -e "${2}" ) ; do
		grep "${SA_SERVICE_PORT}\$" "${SA_SERVICE_TEMP}" &> /dev/null
		if [ $? -ne 0 ]	; then
			sa_print_err 2 "Service ${SA_SERVICE_NAME} failed to bind port ${SA_SERVICE_PORT}."
		# else
		# 	sa_print_err 3 "Service ${SA_SERVICE_NAME} has bound port ${SA_SERVICE_PORT}."
		fi
	done
	rm -f "${SA_SERVICE_TEMP}" &> /dev/null || die "Could not unlink temp file.\n"
}

sa_test_all_services () {
	# Always test appliance service and Puppet agent
	case ${SA_RELEASE_VER} in
		10.3.* )	sa_test_service NwAppliance "50006\n50106"
					;;
		10.4.* )	sa_test_service 'puppet agent' ""
					sa_test_service NwAppliance "56006\n50106"
					;;
		* ) sa_print_err 2 "Internal script error."
			;;
	esac

	case ${SA_RELEASE_VER} in
		10.3.* )
			case ${SA_APPLIANCE_TYPE} in
				SA_PACKET_HYBRID )	sa_test_service NwDecoder "50004\n50104"
									sa_test_service NwConcentrator "50005\n50105"
									;;
				SA_PACKET_DECODER )	sa_test_service NwDecoder "50004\n50104"
									;;
				SA_LOG_DECODER )	sa_test_service NwLogCollector "50001\n50101"
									sa_test_service NwLogDecoder "514\n6514\n50002\n50102\n50202"
									;;
				SA_LOG_HYBRID )		sa_test_service NwLogCollector "50001\n50101"
									sa_test_service NwConcentrator "50005\n50105"
									sa_test_service NwLogDecoder "514\n6514\n50002\n50102\n50202"
									;;
				SA_LOG_COLLECTOR ) 	sa_test_service NwLogCollector "50001\n50101"
									;;
				SA_MALWARE ) 		sa_test_service '^/.*rsamalware' "18443\n160007"
									;;
				SA_SERVER )			sa_test_service lighttpd "80"
									sa_test_service jetty9 "443"
									sa_test_service NwBroker "50003\n50103"
									sa_test_service CAS.py "50010"
									# sa_test_service 'tcp.*50009' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*50025' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
									;;
				SA_SERVER_NO_BROKER )	# sa_test_service NwBroker "50003\n50103"
										sa_test_service lighttpd "80"
										sa_test_service jetty9 "443"
										sa_test_service CAS.py "50010"
										# sa_test_service 'tcp.*50009' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*50025' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
										;;
				SA_CONCENTRATOR )	sa_test_service NwConcentrator "50005\n50105"
									;;
			esac
			;;
		10.4.* )
			case ${SA_APPLIANCE_TYPE} in
				SA_PACKET_HYBRID )	sa_test_service NwDecoder "56004\n50104"
									sa_test_service NwConcentrator "56005\n50105"
									;;
				SA_PACKET_DECODER )	sa_test_service NwDecoder "56004\n50104"
									;;
				SA_LOG_DECODER )	sa_test_service NwLogCollector "56001\n50101"
									sa_test_service NwLogDecoder "514\n6514\n56002\n50102\n50202"
									;;
				SA_LOG_HYBRID )		sa_test_service NwLogCollector "56001\n50101"
									sa_test_service NwConcentrator "56005\n50105"
									sa_test_service NwLogDecoder "514\n6514\n56002\n50102\n50202\n56202"
									;;
				SA_LOG_COLLECTOR ) 	sa_test_service NwLogCollector "56001\n50101"
									;;
				SA_MALWARE ) 		sa_test_service '^/.*rsamalware' "18443\n160007"
									;;
				SA_SERVER )			sa_test_service lighttpd "80"
									sa_test_service jetty9 "443"
									sa_test_service 'puppet master' "8140"
									sa_test_service 'beam\.smp' '5671\n5672\n15671\n25672\n61614'
									sa_test_service mongod "27017\n28017"
									sa_test_service NwBroker "56003\n50103"
									# sa_test_service CAS.py "50010"
									# sa_test_service 'tcp.*50009' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*50025' "IPDB Extractor" native
									# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
									;;
				SA_SERVER_NO_BROKER )	sa_test_service lighttpd "80"
										sa_test_service jetty9 "443"
										sa_test_service 'puppet master' "8140"
										sa_test_service 'beam\.smp' '5671\n5672\n15671\n25672\n61614'
										sa_test_service mongod "27017\n28017"
										# sa_test_service NwBroker "50003\n50103"
										# sa_test_service CAS.py "50010"
										# sa_test_service 'tcp.*50009' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*50025' "IPDB Extractor" native
										# sa_test_firewall_port 'tcp.*50125' "IPDB Extractor" REST
										;;
				SA_CONCENTRATOR )	sa_test_service NwConcentrator "50005\n50105"
									;;
			esac
			;;
		* )	sa_print_err 2 "Internal script error."
			;;
	esac

}

sa_test_single_fs () {
	if [ ${3} -gt ${2} ] ; then
		sa_print_err 2 "${1} usage has exceeded threshold of ${2}% (${3}%)."
	fi
}

sa_test_filesystem_space () {
	for i in $( df -Ph | grep -v -e '^Filesystem[[:space:]]' -e 'dev\/shm' | awk '{print $6","$5}' | sed 's/\%//g' ) ; do
		SA_FS_NAME=$( echo "${i}" | awk -F, '{print $1}' )
		SA_FS_SIZE=$( echo "${i}" | awk -F, '{print $2}' )
		case ${SA_FS_NAME} in
			'/' ) sa_test_single_fs "${SA_FS_NAME}" "50" "${SA_FS_SIZE}" ;;
			'/boot' ) sa_test_single_fs "${SA_FS_NAME}" "75" "${SA_FS_SIZE}" ;;
			'/home' ) sa_test_single_fs "${SA_FS_NAME}" "85" "${SA_FS_SIZE}" ;;
			'/home' ) sa_test_single_fs "${SA_FS_NAME}" "75" "${SA_FS_SIZE}" ;;
			'/home/rsasoc' ) sa_test_single_fs "${SA_FS_NAME}" "90" "${SA_FS_SIZE}" ;;
			'/var/log' ) sa_test_single_fs "${SA_FS_NAME}" "90" "${SA_FS_SIZE}" ;;
			'/var/lib/netwitness' ) sa_test_single_fs "${SA_FS_NAME}" "85" "${SA_FS_SIZE}" ;;
			*packetdb* ) sa_test_single_fs "${SA_FS_NAME}" "96" "${SA_FS_SIZE}" ;;
			*index ) sa_test_single_fs "${SA_FS_NAME}" "90" "${SA_FS_SIZE}" ;;
			*metadb* ) sa_test_single_fs "${SA_FS_NAME}" "96" "${SA_FS_SIZE}" ;;
			*session* ) sa_test_single_fs "${SA_FS_NAME}" "96" "${SA_FS_SIZE}" ;;
			* ) sa_test_single_fs "${SA_FS_NAME}" "60" "${SA_FS_SIZE}" ;;
		esac
	done
}

sa_test_initramfs () {
	# Can we unpack it? Note that cpio does not always return a nonzero exit code
	# on error, so we have to test the output, too...
	for SA_INITRRAMFS_IMG in $( rpm -q kernel | awk -F- '{print $2"-"$3}' ) ; do
		if [ ! -f "/boot/initramfs-${SA_INITRRAMFS_IMG}.img" ] ; then
			sa_print_err 1 "initramfs image for kernel ${SA_INITRRAMFS_IMG} missing!"
			continue
		fi
		SA_INITRAMFS_TEMP=$(mktemp) || die "Could not create temporary file.\n"
		zcat "/boot/initramfs-${SA_INITRRAMFS_IMG}.img" | cpio --extract --quiet --only-verify-crc 1> /dev/null 2> "${SA_INITRAMFS_TEMP}"
		# Note the clever redirection above ^
		if [ $? -ne 0 ] ; then
			sa_print_err 1 "CRC errors were detected while unpacking ${SA_INITRRAMFS_IMG}."
			rm -fr "${SA_INITRAMFS_TEMP}" || die "Could not unlink temp file.\n" ; return 1
		elif [ $( wc -l "${SA_INITRAMFS_TEMP}" | awk '{print $1}' ) -gt 0 ] ; then
			sa_print_err 1 "CRC errors were detected while unpacking ${SA_INITRRAMFS_IMG}."
			rm -fr "${SA_INITRAMFS_TEMP}" || die "Could not unlink temp file.\n" ; return 1
		fi
		zcat "/boot/initramfs-${SA_INITRRAMFS_IMG}.img" | cpio --list 2> /dev/null 1> "${SA_INITRAMFS_TEMP}"
		for SA_INITRAMFS_FILE in 'lib/kbd/consolefonts/..*gz' 'lib/kbd/unimaps/..*uni' \
			'lib/kbd/keymaps/i386/qwerty/..*gz' 'lib/firmware/..*bin' "lib/modules/${SA_INITRRAMFS_IMG}/modules\.dep" \
			'lib/terminfo/l/linux' 'cmdline/..*sh' 'dev/pts' 'bin/mount' 'etc/modprobe.d/..*conf' \
			'etc/ld\.so\.conf\.d' 'etc/udev/udev\.conf' 'etc/ld\.so\.conf' 'lib64/..*' \
			'pre-pivot/..*sh' 'usr/bin/bzip2' 'usr/lib64/..*' 'mount/99mount-root\.sh' \
			'sbin/modprobe' 'init' 'sysroot' ; do
			grep "^${SA_INITRAMFS_FILE}" "${SA_INITRAMFS_TEMP}" &> /dev/null
			if [ $? -ne 0 ] ; then
				sa_print_err 2 "Could not find pattern '${SA_INITRAMFS_FILE}' in initramfs image."
			fi
		done
		# FIXME: Remove
		sa_print_err 3 "Tested /boot/initramfs-${SA_INITRRAMFS_IMG}.img"
	done
	rm -fr "${SA_INITRAMFS_TEMP}" || die "Could not unlink temp file.\n"
}

# This could take a long time. Make optional?
sa_verify_rpms () {
	# Create temp file containing list of installed RPMs
	SA_RPM_LIST_TEMP=`mktemp` || die "Could not create temporary file.\n"

	# Temp file with output of 'rpm -V'
	SA_RPM_OUT=`mktemp` || die "Could not create temporary file.\n"

	rpm -qa &> "${SA_RPM_LIST_TEMP}"
	if [ $? -ne 0 ] ; then
		sa_print_err 0 "The RPM database is in a bad state!"
		rm -f "${SA_RPM_LIST_TEMP}" "${SA_RPM_OUT}" &> /dev/null || die "Could not unlink temp files.\n"
		return 1
	fi
	for SA_RPM_VERIFY in $( cat "${SA_RPM_LIST_TEMP}" ) ; do
		rpm -V "${SA_RPM_VERIFY}" &>> "${SA_RPM_OUT}"
		if [ $? -ne 0 ] ; then
			if [ "$( awk '{print $2}' ${SA_RPM_OUT} )" != "c" ] ; then
				sa_print_err 1 "${SA_RPM_VERIFY} appears corrupt"
			fi
		fi
	done
	rm -f "${SA_RPM_LIST_TEMP}" "${SA_RPM_OUT}" &> /dev/null || die "Could not unlink temp files.\n"
}

# Bare-bones trap handler
handle_trap () {
	die "\nExiting on signal.\n"
}

# Trap signals, just for fun and prettiness
trap handle_trap SIGINT SIGHUP SIGTERM

# Script called with no args?
# if [ $# -eq 0 ] ; then
#	sa_help
# fi

# Parse cmdline args
while getopts ":fhvV" ARGV_OPTS ; do
	case $ARGV_OPTS in
		f ) SA_JUST_RUN=1; ;;
		h ) sa_help ;;
		v ) echo -e "`basename $0` ${SA_DIAG_VER}\n" ; exit 0 ;;
		V ) SA_RUN_IN_VM=1 ;;
		* ) die "Unrecognized option or missing parameter. Use -h for help.\n" ;;
	esac
done ; shift $(( OPTIND - 1 ));

if [[ "${SA_APPLIANCE_HW}" != "R620" && "${SA_APPLIANCE_HW}" != "R610" && "${SA_APPLIANCE_HW}" != "R510" && ${SA_RUN_IN_VM} -ne 1 && ${SA_JUST_RUN} -ne 1 ]] ; then
	sa_print_err 3 "Unsupported hardware revision. Exiting.\n"
	exit 2
fi

# Special-cased test to allow VMs
if [[ ${SA_JUST_RUN} -ne 1 && ${SA_RUN_IN_VM} -ne 1 ]] ; then
	which MegaCli64 &> /dev/null || die "MegaCli64 not available. Cannot continue.\n"
fi

# FIXME: Replace all these calls with something more versatile

echo "Getting appliance type..." ; sa_get_appliance_type ; sa_print_err 3 "Appliance type is ${SA_APPLIANCE_TYPE}." ; \
	sa_print_err 3 "Appliance revision is ${SA_APPLIANCE_HW}, S/N ${SA_APPLIANCE_SN}" ; \
	sa_print_err 3 "Appliance release is ${SA_RELEASE_VER}." ; sa_print_err 3 "Kernel is $( uname -r 2> /dev/null )." ; \
	sa_print_err 3 "OS is $( cat /etc/redhat-release 2> /dev/null )" ; \
	sa_print_err 3 "Default route is $( ip route show | grep ^default 2> /dev/null | sed 's/default //g' )" ; echo
echo "Testing firewall rules..." ; sa_test_firewall ; echo
echo "Finding GRO states..." ; sa_test_gro ; echo
echo "Reticulating splines..." ; sleep 1 ; echo
echo "Parsing NTP state..." ; sa_test_ntp ; echo
echo "Checking Anaconda-related kernel config..." ; sa_test_anaconda ; echo
echo "Examining installed and configured kernels..." ; sa_test_kernel_ver ; echo
echo "Unearthing contents of initramfs images..." ; sa_test_initramfs ; echo
echo "Calculating memory..." ; sa_test_sys_ram ; echo
echo "Frobbing /tmp..." ; sa_test_sys_tmp ; echo
if [ ${SA_RUN_IN_VM} -eq 0 ] ; then
	echo "Evaluating RAID controllers..." ; sa_test_raid_health ; echo
fi
echo "Probing services..." ; sa_test_all_services ; echo
echo "Considering filesystems..." ; sa_test_filesystem_space ; echo
echo "Looking for core files (be patient)..." ; sa_test_corefiles ; echo
# echo "Verifying all packages (lengthy)..." ; sa_verify_rpms
