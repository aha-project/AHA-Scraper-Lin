#!/bin/bash

#Copyright 2018 ESIC at WSU distributed under the MIT license. Please see LICENSE file for further info.
#Author: Eric Hjort, Washington State Univeristy

#TODO:
#Attributes I still need to make a script to get and then parse out:
	#Info we need: ProcessServices, StrongNaming, HighEntropyVA (haven't confirmed this is/isn't on Linux)
	
	#CodeSigning, Authenticode
#		Validate binaries for each PROC binary path
#		Use RPM, TripWire, or something similar
	#ControlFlowIntegrity (CFI)
#		Before a function call, the target address is checked
		#against a table of valid call addresses
		#If the address isn't in the table, the call is aborted. 
#		Clang compiler supports this
	#StrongNaming
	#Scan each binary once and store results, so that if the same binary such as httpd
		#has 100 connections, we only scan httpd once and store the result in a hashtable or similar
	#better chosing of verbosity (i.e. debug vs verbose vs regular outputs)

#Authenticode,StrongNaming,SafeSEH,ControlFlowGuard,HighentropyVA
#END TODO

#Debug variable, controls test printing for each function output
DEBUG=''

#Used to hold the 'cleaned' string 
CleanedString=''

#global variables, one for each field so it's easy to change formatting and
#so that parameters can be used for different queries/scripts 
ProcessName=''		#Name of current PROC
Uid=''			#User ID, had to use 'Uid' and not UID since UID is reserved/readonly
PID=0
ProcessPath=''		#Path to binary of process
Protocol=''		#Networking protocol type
LocalAddress=''
LocalPort=0
LocalPortName=''	
RemoteAddress=''
RemotePort=0
RemoteHostName=''
State=''		#State of process: Established, Close_Wait, Time_Wait, ect...
ProductName=''
FileDescription=''
FileVersion=''
Company=''
ProcessCreatedOn=''
UserName=''
ProcessServices=''
ProcessAttributes=''
DetectionTime=''
ARCH=''			#System Architecture
ASLR=''			#Address Space Layout Randomization
SysASLR=0		#If system has ASLR enabled
PieBinary=0		#Process has PIE enabled
PieProcess=0		#Binary has PIE enabled
DEP=''			#Data Execution Prevention
PIE=''			#Position Independent Executable, implies ASLR is active
Authenticode='N/A'	#Verify authenticity of publisher
StrongNaming='N/A'	#Unique ID for assembly
SafeSEH='N/A'		#DNE for Linux
ControlFlowGuard='N/A'	#DNE for Linux, keep looking
HighEntropyVA='N/A'	#Might exist for Linux
RELRO=''		#Reorders .data and .bss to after other sections
StackCanary=''		#bits, buffer boundary, if corrupted => stack-overflow
PaX=''			#Implements least privilege protections for mem pages


#----------------------------FILE FUNCTIONS-------------------------------------

#Takes currently set ProcessPath and 
#	parses the file information for its description and version (if available)
#Learned: about using 'cut'
file_info () {
	#Check if ProcessPath is null,
	if [ "${ProcessPath}" = '' ] ; then
		FileDescription=''
		FileVersion=''
	else
		#Get the file description
		FileDescription=$(file -b "${ProcessPath}")
		#Get file version from elf header
		FileVersion=$(readelf -h "${ProcessPath}" | grep -w 'Version' | head -1 | tr -d '[:space:]' | cut -d ':' -f 2)
		FileDescription="$(echo $FileDescription | cut -d ',' -f 1)"
	fi
	if [ $DEBUG -gt 1 ] ; then
		echo -e "FileDescription: $FileDescription \nFileVersion: $FileVersion"
	fi
}

#----------------------------PROCESS FUNCTIONS----------------------------------

#Accepts a process pid, gets and sets the path of the given process' binary
#Learned: Location of process binaries, how to select specific output of tokenized string
proc_path() {	
	if [ $DEBUG -gt 3 ] ; then
		echo "proc_path()"
	fi
	#Check if PID is empty
	if [ "$PID" = '0' ] ; then
		ProcessPath=""
		return
	fi
	#Check if file exists
	if [ -f /proc/$PID/exe ] ; then
		#Select path from output
		ProcessPath="$(ls -al /proc/$PID/exe | sed -e 's/.* -> //')"

	else
		if [ $DEBUG -gt 0 ] ; then
			echo "	Path /proc/$PID/exe does not exist"
		fi
		ProcessPath=''
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo "ProcessPath: |"${ProcessPath}"|"
	fi
}

#Gets the process name for current user
proc_user_name() {
	if [ $DEBUG -gt 3 ] ; then
		echo "proc_user_name()"
	fi
	#Check if PID is empty
	if [ "$PID" = '0' ] ; then
		UserName=""
		return
	fi
	#remove leading and duplicate spaces
	UserName=$(ps -eo uname,pid | grep $PID |  cut -d ' ' -f 1)
	if [ $DEBUG -gt 1 ] ; then
		echo "UserName: $UserName"
	fi
}

#Takes the currently set PID and finds when it was created
#Learned how to return a single line from grep using 'head'
proc_created_on() {
	if [ $DEBUG -gt 3 ] ; then
		echo "proc_created_on()"
	fi
	#Check if PID is empty
	if [ "$PID" = '0' ] ; then
		ProcessCreatedOn=""
		return
	fi
	local counter=1
	#Get current date and iterate over to extract the month, day, time, and year
	local epoch=$(date +%s)
	#Select time information for PID and clean string
	local elapsed=$(ps -eo pid,etimes | grep -w "$PID") ; clean_string "$elapsed" ; elapsed=$CleanedString
	#select time elapsed
	elapsed=$(echo "$elapsed" | cut -d ' ' -f 2)
	if [ $DEBUG -gt 2 ] ; then
		echo -e "\tepoch: |$epoch|\n\telapsed: |$elapsed|"
	fi
	local creation=$(echo $(($epoch-$elapsed)))
	for var in $(date -d "@$creation" | tr -s ' ' | cut -d ' ' -f 2,3,4,6); do 
		case $counter in 
				1)
					local month=$var
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tMonth: $var"
					fi
				;;
				2)
					local day=$var
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tDay: $day"
					fi
				;;
				3)
					#Split var into 2
					local hour=$(echo $var | cut -d ':' -f 1)
					local min=$(echo $var | cut -d ':' -f 2)
					local time=$(echo "$hour:$min")
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tTime: $time"
					fi
				;;
				4)
					local year=$var
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tYear: $year"
					fi
				;;
				*)
					continue
			esac
		((counter++))
		done
	
	ProcessCreatedOn=$(echo "$day/$month/$year $time")
	if [ $DEBUG -gt 1 ] ; then
		echo "ProcessCreatedOn: $ProcessCreatedOn"
	fi 
}


#-------------------------AUXHILARY FUNCTIONS-----------------------------------

#Cleans the input string and echos result for return
#Learned: How to remove special chars using 'sed' and tr 
#TODO: Make a filter of allowed characters instead of deleting ones we don't want
clean_string () {
	if [ $DEBUG -gt 3 ] ; then
		echo "clean_string()"
	fi
	#remove leading and duplicate spaces
	local string=$(echo $1 | awk '{$2=$2};1')
	#Remove unusable single quotes from variable
	CleanedString=$(echo $string | tr -d '\47\140')
}

#Sets architecture
#Learned how to use uname and how to use awk functions to conver to upper
#TODO: Add support for other architecture, use a 'case' structure
architecture () {
	if [ $DEBUG -gt 3 ] ; then
		echo "architecture():"
	fi
	#Check if AMD64
	if [[ "$(uname -r)" = *'x86_64'* ]]; then
		ARCH='AMD64'
	else
		ARCH='N/A'
		if [ $DEBUG -gt 0 ] ; then
			echo 'Unknown Arch, Currently Unsupported (in development)'
		fi
	fi
	#NOTE:This information can be found in: /proc/sys/kernel/osrelease
	if [ $DEBUG -gt 1 ] ; then
		echo "Architecture: $ARCH "
	fi
}


#Sets the current detection time
detection_time () {
	if [ $DEBUG -gt 3 ] ; then
		echo "	detection_time():"
	fi
	counter=1
	#Get current date and iterate over to extract the month, day, time, and year
	for var in $(date -d seconds | tr -s '[:space:]' | cut -d ' ' -f 2,3,4,6); do 
		case $counter in 
				1)
					month=$var
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tMonth: $var"
					fi
				;;
				2)
					day=$var
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tDay: $day"
					fi
				;;
				3)
					#Split var into 2
					hour=$(echo $var | cut -d ':' -f 1)
					min=$(echo $var | cut -d ':' -f 2)
					time=$(echo "$hour:$min")
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tTime: $time"
					fi
				;;
				4)
					year=$var
					if [ $DEBUG -gt 2 ] ; then 
						echo -e "\t\tYear: $year"
					fi
				;;
				*)
					continue
			esac
		((counter++))
		done
	DetectionTime=$(echo "$day/$month/$year $time")
	if [ $DEBUG -gt 0 ] ; then
		echo "DetectionTime: $DetectionTime"
	fi
}


#This function takes the output from netstat and parses the information so it may be placed into global variables where they're 
#	analyzed and their output is printed to a CSV
#Learned: How to parse line-by-line from tool output, remove duplicate characters using 'tr' , nested loops, switch statements, counters, arithmetic, how to delimit on last character of a string
parse_netstat() {
	counter=1
	#Set IFS to newline and include entire loop in parenthesis so IFS can be set to parse on spaces
	(IFS='
	'
	#read each line from the netstat output
	for line in $(netstat -ventap); do 
		#Select fields we want and put into an array
		array=$(echo $line | tr -s '[:space:]' | cut -d ' ' -f 1,4,5,6,7,8,9)
		#Change Field Separator to space
		IFS=' '
		#remove extra spaces from the input line, split into vars, and interate over result 
		for var in $(echo $line | tr -s '[:space:]' | cut -d ' ' -f 1,4,5,6,7,9); do
			#Skip over first two lines of output from netstat
			if [ $var = "Active" ] || [ $var = "Proto" ] ; then
				break
			fi
			
			#set vars based on counter, position in array
			case $counter in 
				1)
					Protocol=$( echo $var | awk '{print toupper($0)}')
					if [[ "$Protocol" = 'TCP'* ]] ; then
						Protocol='TCP'
					elif [[ "$Protocol" = 'UDP'* ]] ; then
						Protocol='UDP'
					fi
					if [ $DEBUG -gt 1 ] ; then 
						echo "Protocol: |$Protocol|"
					fi
				;;
				2)
					string=$var
					#Find last occurrence of ':'
					for ((i=${#string}; i>-1; i--)); do 
						#if current char is ':'
						if [ "${string:$i:1}" = ':' ] ; then
							break
						fi
					done
					LocalAddress=$( echo "${string:0:$i}")
					#Get port by printing out last element at index 'NF' and remove any non-numbers
					LocalPort=$(echo $var | awk -F ':' '{print $NF}' | tr -d '[:space:]' | tr -cd '\60-\71')
					LocalPortName=$(getent services $LocalPort | cut -d ' ' -f 1 | tr -d '[:space:]')
					LocalPortName=''
					#Check for TCP connection
					if [ $DEBUG -gt 1 ] ; then 
						echo "LocalAddress: |$LocalAddress|"
						echo "LocalPort: |$LocalPort|"
						#echo "LocalPortName: $LocalPortName"
					fi
				;;
				3)
					#Split var into 2
					string=$var
					#Find last occurrence of ':'
					for ((i=${#string}; i>-1; i--)); do 
						#string split for comparison
						if [ "${string:$i:1}" = ':' ] ; then
							break
						fi
					done
					RemoteAddress=$( echo "${string:0:$i}" | tr -s ':')
					#Get port by printing out last element at index 'NF' and remove any non-numbers
					RemotePort=$(echo $var | cut -d ':' -f 2 | tr -d '[:space:]'| tr -cd '\60-\71')
					#Check for empty port name
					if [ "$RemotePort" != "" ] ; then
						RemotePortName=$(getent services $RemotePort | cut -d ' ' -f 1 | tr -d '[:space:]')
					else
						RemotePortName=''
					fi
					
					if [ $DEBUG -gt 1 ] ; then 
						echo "RemoteAddress: |$RemoteAddress|"
						echo "RemotePort: |$RemotePort|"
						#echo "RemotePortName: $RemotePortName"
					fi
				;;
				4)
					State=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo "State: |$State|"
					fi
					
					if [[ "$State" = 'LISTEN'* ]] ; then
						State='LISTENING'
						RemoteAddress=''
						RemotePort=''
						RemotePortName=''
						if [ $DEBUG -gt 1 ] ; then
							echo -e '\tLISTENING State. Setting: Address, Remote Port and PortName to empty strings '' for CSV output'
						fi
					fi
				;;
				5)
					Uid=$var #NOTE: this may not be accurate
					if [ $DEBUG -gt 1 ] ; then 
						echo "Uid: |$Uid|"
					fi
				;;
				6)
					#Split var into 2, delete trailing space from PID
					#NOTE: Cut doesn't always work with '/' if it's not formatted this way: "cut -d/" instead of "cut -d '/'"
					PID=$(echo $var | cut -d/ -f 1 | awk '{$1=$1;print}')
					#Get ProcName, only include letters
						string=$var
					#Find last occurrence of '/'
					for ((i=${#string}; i>-1; i--)); do 
						#if current char is ':'
						if [ "${string:$i:1}" = '/' ] ; then
							break
						fi
					done
					ProcessName=$( echo "${string:(($i+1)):${#string}}")
					clean_string "$ProcessName" ; ProcessName=$CleanedString
					#Strip out unusable chars for ProcName  : / \
					ProcessName=$(echo $ProcessName | tr -d '\57\72\134')
					
					if [[ "$ProcessName" = '-' ]] || [[ "$ProcessName" = '' ]] ; then
						ProcessName='Unknown'
					fi
					
					if [[ "$PID" = '-' ]] ; then
						PID='0'
					fi 
					if [ $DEBUG -gt 1 ] ; then 
						echo "PID: |$PID|"
						echo "ProcessName: |$ProcessName|"
					fi
					#get process info
					process_wrapper
					#get binary info
					binary_wrapper
					#Check for system-wide ASLR
					if [[ "$SysASLR" = 'TRUE' ]] && [[ "$PieBinary" = 'TRUE' ]] && [[ "$PieProcess" = 'TRUE' ]] ; then
						ASLR='TRUE'
					else
						ASLR='FALSE'
					fi
					if [ $DEBUG -gt 1 ] ; then
						echo -e "ASLR: $ASLR\n\tSysASLR: $SysASLR\n\tPieBinary: $PieBinary\n\tPieProcess: $PieProcess"
					fi
					#Print Data To File
					echo "\"$ProcessName\",\"$PID\",\"$ProcessPath\",\"$Protocol\",\"$LocalAddress\",\"$LocalPort\",\"$LocalPortName\",\"$RemoteAddress\",\"$RemotePort\",\"$RemoteHostName\",\"$RemotePortName\",\"$State\",\"$ProductName\",\"$FileDescription\",\"$FileVersion\",\"$Company\",\"$ProcessCreatedOn\",\"$UserName\",\"$ProcessServices\",\"$ProcessAttributes\",\"$DetectionTime\",\"$ARCH\",\"$ASLR\",\"$DEP\",\"$RELRO\",\"$StackCanary\"" >> BinaryAnalysis.csv
					#reset counter and show break line
					counter=1
					if [ $DEBUG -eq 0 ] ; then
						echo -e "ProcessName: $ProcessName\tPID: $PID\tProcessPath: $ProcessPath"
					fi
					if [ $DEBUG -gt 0 ] ; then
						echo -e "-----------------------------\n"
					fi
					break
				;;
				*)
					continue
			esac
		((counter++))
		done
	done)
}


#----------------------------MAIN FUNCTION / WRAPPERS --------------------------
#This function controls the logic flow of the program and is called to execute
aha_wrapper() {
	echo "AHA-Linux-Scraper: Scanning System..."
	architecture
	detection_time
	#output header info to file
	echo -e "\"ProcessName\",\"PID\",\"ProcessPath\",\"Protocol\",\"LocalAddress\",\"LocalPort\",\"LocalPortName\",\"RemoteAddress\",\"RemotePort\",\"RemoteHostName\",\"RemotePortName\",\"State\",\"ProductName\",\"FileDescription\",\"FileVersion\",\"Company\",\"ProcessCreatedOn\",\"UserName\",\"ProcessServices\",\"ProcessAttributes\",\"DetectionTime\",\"ARCH\",\"ASLR\",\"DEP\",\"RELRO\",\"StackCanary\"" > BinaryAnalysis.csv
	#parse output from netstat and call process/binary wrappers for each output line
	parse_netstat
}

#Called in Netstat ~line 370
process_wrapper() {
	proc_path
	proc_created_on
	proc_user_name
	PIE_Process
	ASLR
	proccheck
}

#Called in Netstat ~line 372
binary_wrapper() {
	file_info
	PIE_Binary
}

#Check for verbose output
if [[ "$1" = '--verbose' ]] ; then
	DEBUG=4
else
	DEBUG=0
fi

#include source files for function calls
DIR="${BASH_SOURCE%/*}"
. "$DIR/deps/checksec/checksec.sh"
#start scraper
aha_wrapper
