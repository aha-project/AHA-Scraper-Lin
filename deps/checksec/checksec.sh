#!/bin/bash

#The functions in this file have been adapted from their original sources to 
#better suit the output or logic required for the AHA project
#
# The BSD License (http://www.opensource.org/licenses/bsd-license.php) 
# specifies the terms and conditions of use for checksec.sh:
#
# Copyright (c) 2009-2011, Tobias Klein.
# All rights reserved.
# Modified by Eric Hjort, Washington State Univeristy
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions 
# are met:
# 
# * Redistributions of source code must retain the above copyright 
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright 
#   notice, this list of conditions and the following disclaimer in 
#   the documentation and/or other materials provided with the 
#   distribution.
# * Neither the name of Tobias Klein nor the name of trapkit.de may be 
#   used to endorse or promote products derived from this software 
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
# DAMAGE.
#
# Name    : checksec.sh
# Version : 1.5
# Author  : Tobias Klein
# Date    : November 2011
# Download: http://www.trapkit.de/tools/checksec.html
# Changes : http://www.trapkit.de/tools/checksec_changes.txt
#
# Description:
#
# Modern Linux distributions offer some mitigation techniques to make it 
# harder to exploit software vulnerabilities reliably. Mitigations such 
# as RELRO, NoExecute (NX), Stack Canaries, Address Space Layout 
# Randomization (ASLR) and Position Independent Executables (PIE) have 
# made reliably exploiting any vulnerabilities that do exist far more 
# challenging. The checksec.sh script is designed to test what *standard* 
# Linux OS and PaX (http://pax.grsecurity.net/) security features are being 
# used.
#
# As of version 1.3 the script also lists the status of various Linux kernel 
# protection mechanisms.
#
# Credits:
#
# Thanks to Brad Spengler (grsecurity.net) for the PaX support.
# Thanks to Jon Oberheide (jon.oberheide.org) for the kernel support.
# Thanks to Ollie Whitehouse (Research In Motion) for rpath/runpath support.
# 
# Others that contributed to checksec.sh (in no particular order):
#
# Simon Ruderich, Denis Scherbakov, Stefan Kuttler, Radoslaw Madej,
# Anthony G. Basile, Martin Vaeth and Brian Davis. 
#

#Source:checksec.sh
#Detects if ASLR is enabled for the system
ASLR () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nASLR()"
	fi
	#Check if PID is empty
	if [ "$PID" = '0' ] ; then
		SysASLR="ScanError"
		return
	fi
	if !(cat /proc/$PID/status 2> /dev/null | grep -q 'Name:') ; then
		echo -e '\tCant perform ASLR Check; priviledge too low'
		echo -n -e '\tUsing Standard ASLR Check\n'
	fi
	if cat /proc/$PID/status 2> /dev/null | grep -q 'PaX:'; then
		echo ": "
		if cat /proc/1/status 2> /dev/null | grep 'PaX:' | grep -q 'R'; then
			echo -e '\tASLR enabled'
		else
			echo -e '\tASLR disabled'
		fi
	else
	# standard Linux 'kernel.randomize_va_space' ASLR support
	# (see the kernel file 'Documentation/sysctl/kernel.txt' for a detailed description)
		#Partial
		if sysctl -a 2> /dev/null | grep -q 'kernel.randomize_va_space = 1'; then
			SysASLR='PARTIAL'
		#True
		elif sysctl -a 2> /dev/null | grep -q 'kernel.randomize_va_space = 2'; then
			SysASLR='TRUE'
		#Has, but is disabled
		elif sysctl -a 2> /dev/null | grep -q 'kernel.randomize_va_space = 0'; then
			SysASLR='DISABLED'
		#System does not have ASLR
		else
			SysASLR='FALSE'
		fi
	fi 
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tSysASLR: |$SysASLR|"
	fi
}


#Check binary for PIE support, implies ASLR is enabled for the binary
#Changes:
PIE_Binary() {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nPIE_Binary()"
	fi
	#Check for empty path
	if [ "${ProcessPath}" = '' ] ; then
		PieBinary='ScanError'
	else
		type=$(readelf -h "${ProcessPath}" | grep 'Type:')
		if [[ "$type" = *'EXEC'* ]] ; then
			PieBinary='FALSE'
		#If ELF is a dynamic shared object
		elif [[ "$type" = *'DYN'* ]] ; then
			PieBinary='TRUE'
		fi
	fi
}

#Check process for PIE support, implies ASLR is enabled for the process
#Changes:
	#Modified readelf to return string for comparison
	#Added in variable assignment
PIE_Process() {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nPIE_Process()"
	fi
	#Check for empty path
	if [ "$PID" = '0' ] ; then
		PieProcess='ScanError'
	else
		#Read header of process and get the type
		type=$(readelf -h /proc/$PID/exe| grep -w 'Type:')
		if [[ "$type" = *'EXEC'* ]] ; then
			PieProcess='FALSE'
		elif [[ "$type" = *'DYN'* ]] ; then
			PieProcess='TRUE'
		else
			if [ $DEBUG -gt 0 ] ; then
				echo -e '\tInput is not an ELF file, cannot determine if PIE'
			fi
			PieProcess='FALSE'
		fi
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tPieProcess: |$PieProcess|"
	fi
}

#Check for execute permissions on the binary
#Changes:
	#Changed readelf for string processing
	#Added in variable support
#Learned: How to check ELF parameters for execute permissions
DEP_NX_Enabled () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nDEP_NX_Enabled()"
	fi
	if [[ "${ProcessPath}"='' ]] ; then
		DEP='ScanError'
	fi
	type=$(readelf -l "${ProcessPath}" | grep 'GNU_STACK' | tr -s ' ' | cut -d ' ' -f 8)
	#If Execution bit is present, then NX is not enabled
	if [ "$type" = 'RWE' ] ; then
		DEP='FALSE'
	else
		DEP='TRUE'
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tDEP: |$DEP|"
	fi
}

#RELRO support
#Changes: 
	#Included colon in Program Headers:
	#removed /exe from readelf path; ProcessPath is an executable
	#Modified outputs and variable assignments
RELRO ()
{
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nRELRO()"
	fi
	if [[ "${ProcessPath}"='' ]] ; then
		RELRO='ScanError'
	fi
	#Check if we can access Program Header information
	if readelf -l "${ProcessPath}" | grep -q 'Program Headers:'; then
		#Check for RELRO support
		if readelf -l "${ProcessPath}" 2>/dev/null | grep -q 'GNU_RELRO'; then
			if readelf -d "${ProcessPath}" 2>/dev/null | grep -q 'BIND_NOW'; then
				if [ $DEBUG -gt 1 ] ; then
					echo -e '\tFull RELRO'
				fi
				RELRO='TRUE'
			else
				if [ $DEBUG -gt 1 ] ; then
					echo -e '\tPartial RELRO'
				fi
				RELRO='PARTIAL'
			fi
		else
			if [ $DEBUG -gt 1 ] ; then
				echo -e '\tNo RELRO support found'
			fi
			RELRO='FALSE'
		fi
	else
		if [ $DEBUG -gt 0 ] ; then
			echo -e '\tCannot read Program Headers. Please run as root.'
		fi
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tRELRO: |$RELRO|"
	fi
}

#StackCanary Support
	#Changes:
		#removed /exe from readelf path; ProcessPath is an executable
		#Modified outputs and variable assignments
Stack_Canary () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nStack_Canary()"
	fi
	if [[ "${ProcessPath}"='' ]] ; then
		StackCanary='ScanError'
	fi
	if readelf -s "${ProcessPath}" 2>/dev/null | grep -q 'Symbol table'; then
		if readelf -s "${ProcessPath}" 2>/dev/n,ull | grep -q '__stack_chk_fail'; then
			if [ $DEBUG -gt 1 ] ; then
				echo -e '\tStackCanary found'
			fi
			StackCanary='TRUE'
		else
			if [ $DEBUG -gt 1 ] ; then
				echo -e '\tNo StackCanary found'
			fi
			StackCanary='FALSE'
		fi
	else
		if [ $DEBUG -gt 0 ] ; then
			echo -e "\tCannot read Symbol table. Please run as root.\n\t If running as root, then the symbol table does not exist for $ProcessPath"
		fi
		StackCanary='FALSE'
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tStack Canary: |$StackCanary|"
	fi
}

# check process(es)
proccheck() {
	if [ "${ProcessPath}" = '' ] ; then
		RELRO='ScanError'
		StackCanary='ScanError'
		DEP='ScanError'
	else
		RELRO
		Stack_Canary
		DEP_NX_Enabled
	fi
}
