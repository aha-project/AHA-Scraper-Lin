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
DuplicateEntry='FALSE'	#Flag for duplicate entry

#----------------------------FILE FUNCTIONS-------------------------------------

#Parses the ProcessPath file info for its description and version (if available)
#Learned: about using 'cut'
file_info () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nfile_info()"
	fi
	#Check if ProcessPath is null,
	if [[ "${ProcessPath}" = '' ]] ; then
		FileDescription=''
		FileVersion=''
	else
		#Get the file description
		FileDescription=$(file -b "${ProcessPath}")
		#Get file version from elf header
		FileVersion=$(readelf -h "${ProcessPath}" | grep -w 'Version' | head -1 | tr -d '[:space:]' | cut -d ':' -f 2)
		FileDescription="$(echo $FileDescription | cut -d ',' -f 1)"
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tFileDescription: $FileDescription \n\tFileVersion: $FileVersion"
	fi
}

#----------------------------PROCESS FUNCTIONS----------------------------------

#Gets and sets the path of the given process' binary using PID
#Learned: Location of process binaries, how to select specific output of tokenized string
proc_path() {	
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nproc_path()"
	fi
	#Check if PID is empty
	if [[ "$PID" = '0' ]] ; then
		ProcessPath=''
		return
	fi
	#Check if file exists
	if [ -f /proc/$PID/exe ] ; then
		#Select path from output
		ProcessPath="$(ls -al /proc/$PID/exe | sed -e 's/.* -> //')"

	else
		if [ $DEBUG -gt 0 ] ; then
			echo -e "\tPath /proc/$PID/exe does not exist"
		fi
		ProcessPath=''
	fi
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tProcessPath: |"${ProcessPath}"|"
	fi
}

#Gets the process name for current user using ps and PID
proc_user_name() {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nproc_user_name()"
	fi
	#Check if PID is empty
	if [[ "$PID" = '0' ]] ; then
		UserName=''
		return
	fi
	#remove leading and duplicate spaces
	UserName="$(ps -eo uname,pid | grep $PID |  cut -d ' ' -f 1 | awk '$1=$1' )" 
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tUserName: |$UserName|"
	fi
}

#Takes the currently set PID and finds when it was created
#Learned how to return a single line from grep using 'head'
proc_created_on() {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nproc_created_on()"
	fi
	#Check if PID is empty
	if [[ "$PID" = '0' ]] ; then
		ProcessCreatedOn=''
		return
	fi
	#Index of variable in parser below
	local counter=1
	#Get current date in seconds
	local epoch=$(date +%s)
	#Select time information for PID and clean string
	local elapsed=$(ps -eo pid,etimes | grep -w "$PID") ; clean_string "$elapsed" ; elapsed=$CleanedString
	#Select time running/elapsed for current PID
	elapsed=$(echo "$elapsed" | cut -d ' ' -f 2 | awk '$1=$1')
	if [ $DEBUG -gt 2 ] ; then
		echo -e "\tepoch: |$epoch|\n\telapsed: |$elapsed|"
	fi
	#Calculate creation date / time in seconds
	local creation=$(echo $(($epoch-$elapsed)))
	#Parse date information based on creation time
	for var in $(date -d "@$creation" | tr -s ' ' | cut -d ' ' -f 2,3,4,6); do 
		case $counter in 
				1)
					local month=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tMonth: |$var|"
					fi
				;;
				2)
					local day=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tDay: |$day|"
					fi
				;;
				3)
					#Split var into 2
					local hour=$(echo $var | cut -d ':' -f 1)
					local min=$(echo $var | cut -d ':' -f 2)
					local time=$(echo "$hour:$min")
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tTime: |$time|"
					fi
				;;
				4)
					local year=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tYear: |$year|"
					fi
				;;
				*)
					continue
			esac
		((counter++))
		done
	
	ProcessCreatedOn=$(echo "$day/$month/$year $time")
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tProcessCreatedOn: |$ProcessCreatedOn|"
	fi 
}


#-------------------------AUXHILARY FUNCTIONS-----------------------------------


#Checks if a PID has already been scanned and skips scanning / sets saved vars if duplicate PID 
#NOTE: This function cannot support debugging due to the echo return variable. 
#	There was issues with local scoping within the loops that did not allow for a variable to be
#	set within since each loop is technically a subshell / child of the parent shell process
#Learned: About function scope and how to bypass function return limitations using shared registers (didn't need to use, but still cool)
pid_check() {
	local dup='FALSE'
	local index=1
	#Set Internal Field Separator to newline
	(IFS='
	'
	#get whole line from PIDRecords.txt
	for line in $(cat PIDRecords.txt); do
		#check if duplicate entry was found
		if [[ "$dup" = 'TRUE' ]] ; then
			echo "TRUE"
			break
		fi
		#echo used for manual testing 
		#echo "line: |$line|"

		#Clear IFS buffer. If not done, nested loop will lose IFS and can't parse correctly
		IFS=' '
		#remove quotes from input line
		line=$(echo $line | tr -d '\42')
		#TODO: The cleaned line is being stripped of its IFS for some reason...
		#echo "cleaned line: |$line|"
		#Set Internal Field Separator to comma to tokenize line
		IFS=','
		#iterate over each variable in the tokenized line
		for var in $(echo "$line"); do
			#echo used for manual testing 
			#echo "var: |$var| pid: |$PID|"
			#echo "index: |$index|"
			
			#if duplicate entry, copy over variables
			if [ "$var" = "$PID" ] || [ "$dup" = 'TRUE' ] ; then
				dup='TRUE'
				#set vars based on counter, position in array variable
				case $index in 
					1)
						#echo used for manual testing 
#						echo "Inner DuplicateEntry: $dup
#						duplicate entry found: $PID
#						"
						#does nothing, skip entry
					;;
					2)
						ProcessName=$var
					;;
					3)
						ProcessPath=$var
					;;
					4)
						ProcessCreatedOn=$var
					;;
					5)
						UserName=$var
					;;
					6)
						PieProcess=$var
					;;
					7)
						SysASLR=$var
					;;
					8)
						RELRO=$var
					;;
					9)
						StackCanary=$var
					;;
					10)
						DEP=$var
					;;
					11)
						FileDescription=$var
					;;
					12)
						FileVersion=$var
					;;
					13)
						PieBinary=$var
					;;
					*)
						break
				
				esac
			else
				break
			fi #end if 
		((index++))
		done
	done)
	#no duplicate found, echo false
	echo "FALSE"
}

#Prints out the information for a duplicate entry, instead of having it 
duplicate_entry() {
	echo -e '\nduplicate_entry()'
	
	#TODO: Read information from file, probably pass in the 
	
	echo -e "\tProcessName: |$ProcessName|"
	echo -e "\tProcessPath: |$ProcessPath|"
	echo -e "\tProcessCreatedOn: |$ProcessCreatedOn|"
	echo -e "\tPieProcesss: |$PieProcesss|"
	echo -e "\tUserName: |$UserName|"
	echo -e "\tSysASLR: |$SysASLR|"
	echo -e "\tRELRO: |$RELRO|"
	echo -e "\tStackCanary: |$StackCanary|"
	echo -e "\tDEP: |$DEP|"
	echo -e "\tFileDescription: |$FileDescription|"
	echo -e "\tFileVersion: |$FileVersion|"
	echo -e "\tPieBinary: |$PieBinary|"
}

#Cleans the input string and echos result for return
#Learned: How to remove special chars using 'sed' and tr 
#TODO: Make a filter of allowed characters instead of deleting ones we don't want
clean_string () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tclean_string()"
	fi
	#remove leading and duplicate spaces
	local string=$(echo $1 | awk '{$1=$1};1')
	#Remove unusable single quotes from variable
	CleanedString=$(echo $string | tr -d '\47\140')
}

#Sets architecture
#Learned how to use uname and how to use awk functions to convert lower to upper
#TODO: Add support for other architecture, use a 'case' structure
architecture () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\narchitecture():"
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
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tArchitecture: $ARCH "
	fi
}


#Sets detection time for current processs
detection_time () {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\ndetection_time():"
	fi
	local counter=1
	#Get current date and iterate over to extract the month, day, time, and year
	for var in $(date -d seconds | tr -s '[:space:]' | cut -d ' ' -f 2,3,4,6); do 
		case $counter in 
				1)
					month=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tMonth: |$var|"
					fi
				;;
				2)
					day=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tDay: |$day|"
					fi
				;;
				3)
					#Split var into 2
					hour=$(echo $var | cut -d ':' -f 1)
					min=$(echo $var | cut -d ':' -f 2)
					time=$(echo "$hour:$min")
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tTime: |$time|"
					fi
				;;
				4)
					year=$var
					if [ $DEBUG -gt 1 ] ; then 
						echo -e "\t\tYear: |$year|"
					fi
				;;
				*)
					continue
			esac
		((counter++))
		done
	DetectionTime=$(echo "$day/$month/$year $time")
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\tDetectionTime: |$DetectionTime|"
	fi
}


#Parses and analyzes output from netstat, places info into global vars and calls helper functions
#Learned: How to parse line-by-line from tool output, remove duplicate characters using 'tr' , nested loops, switch statements, counters, arithmetic, how to delimit on last character of a string
parse_netstat() {
	if [ $DEBUG -gt 0 ] ; then
		echo -e "\nparse_netstat()"
	fi
	local counter=1
	#Sets IFS to newline for parsing. 
		#Entire loop is in parenthesis so IFS can be set to parse on spaces for internal loop
	(IFS='
	'
	#read each line into 'line' from the netstat output, parsed on newline char
	for line in $(netstat -ventap); do 
		#Change Internal Field Separator (IFS) to space
		IFS=' '
		#Trim extra spaces, split into vars, and interate over result 
		for var in $(echo $line | tr -s '[:space:]' | cut -d ' ' -f 1,4,5,6,7,9); do
			#Skip over first two lines of output from netstat
			if [[ $var = "Active" ]] || [[ $var = "Proto" ]] ; then
				break
			fi
			
			#set vars based on counter, position in array variable
			case $counter in 
				1)
					Protocol=$(echo $var | awk '{print toupper($0)}')
					if [[ "$Protocol" = 'TCP'* ]] ; then
						Protocol='TCP'
					elif [[ "$Protocol" = 'UDP'* ]] ; then
						Protocol='UDP'
					fi
					if [ $DEBUG -gt 0 ] ; then 
						echo -e "\tProtocol: |$Protocol|"
					fi
				;;
				2)
					string=$var
					#Find last occurrence of ':'
					for ((i=${#string}; i>-1; i--)); do 
						#if current char is ':'
						if [[ "${string:$i:1}" = ':' ]] ; then
							break
						fi
					done
					LocalAddress=$(echo "${string:0:$i}")
					#Get port by printing out last element at index 'NF' and remove any non-numbers
					LocalPort=$(echo $var | awk -F ':' '{print $NF}' | tr -d '[:space:]' | tr -cd '\60-\71')
					LocalPortName=$(getent services $LocalPort | cut -d ' ' -f 1 | tr -d '[:space:]')
					LocalPortName=''
					#Check for TCP connection
					if [ $DEBUG -gt 0 ] ; then 
						echo -e "\tLocalAddress: |$LocalAddress|"
						echo -e "\tLocalPort: |$LocalPort|"
						#echo -e "\tLocalPortName: $LocalPortName"
					fi
				;;
				3)
					#Split var into 2
					string=$var
					#Find last occurrence of ':'
					for ((i=${#string}; i>-1; i--)); do 
						#string split for comparison
						if [[ "${string:$i:1}" = ':' ]] ; then
							break
						fi
					done
					RemoteAddress=$(echo "${string:0:$i}" | tr -s ':')
					#Get port by printing out last element at index 'NF' and remove any non-numbers
					RemotePort=$(echo $var | cut -d ':' -f 2 | tr -d '[:space:]'| tr -cd '\60-\71')
					#Check for empty port name
					if [[ "$RemotePort" != "" ]] ; then
						RemotePortName=$(getent services $RemotePort | cut -d ' ' -f 1 | tr -d '[:space:]')
					else
						RemotePortName=''
					fi
					
					if [ $DEBUG -gt 0 ] ; then 
						echo -e "\tRemoteAddress: |$RemoteAddress|"
						echo -e "\tRemotePort: |$RemotePort|"
						#echo -e "\tRemotePortName: $RemotePortName"
					fi
				;;
				4)
					State=$var
					if [[ "$State" = 'LISTEN'* ]] ; then
						State='LISTENING'
						RemoteAddress=''
						RemotePort=''
						RemotePortName=''
						if [ $DEBUG -gt 0 ] ; then
							echo -e '\t\tLISTENING State. \n\t\t   Setting: Address, Remote Port, and PortName to empty strings for CSV output'
						fi
					fi
					if [ $DEBUG -gt 0 ] ; then 
						echo -e "\tState: |$State|"
					fi
				;;
				5)
					Uid=$var #NOTE: this may not be accurate
					if [ $DEBUG -gt 0 ] ; then 
						echo -e "\tUID: |$Uid|"
					fi
				;;
				6)
					
					#Split var into 2, delete trailing space from PID
					#NOTE: Cut doesn't always work with '/' if it's not formatted this way: "cut -d/" instead of "cut -d '/'"
					PID=$(echo $var | cut -d/ -f 1 | awk '{$1=$1;print}')
					if [[ "$PID" = '-' ]] ; then
						PID='0'
					fi 
					#echo "call pid_check"
					#Check if PID exists
					DuplicateEntry=$(pid_check)
					if [[ "$DuplicateEntry" = 'TRUE' ]] ; then
						DuplicateEntry='TRUE'
					else
						DuplicateEntry='FALSE'
					fi
					if [[ "$DuplicateEntry" = 'FALSE' ]] ; then
						#Get ProcName, only include letters
						string=$var
						#Find last occurrence of '/'
						for ((i=${#string}; i>-1; i--)); do 
							#if current char is ':'
							if [[ "${string:$i:1}" = '/' ]] ; then
								break
							fi
						done
						#Slice string from last '/' to final char
						ProcessName=$(echo "${string:(($i+1)):${#string}}")
						clean_string "$ProcessName" ; ProcessName=$CleanedString
						#Strip out unusable chars for ProcName  : / \
						ProcessName=$(echo $ProcessName | tr -d '\57\72\134')
					
						if [[ "$ProcessName" = '-' ]] || [[ "$ProcessName" = '' ]] ; then
							ProcessName='Unknown'
						fi
					
						
						if [ $DEBUG -gt 0 ] ; then 
							echo -e "\tPID: |$PID|  "
							echo -e "\tProcessName: |$ProcessName|"
						fi
					
							#get process info
							process_wrapper
							#get binary info
							binary_wrapper
							#Add entry to PIDArray
							echo "\"$PID\",\"$ProcessName\",\"$ProcessPath\",\"$ProcessCreatedOn\",\"$UserName\",\"$PieProcess\",\"$SysASLR\",\"$RELRO\",\"$StackCanary\",\"$DEP\",\"$FileDescription\",\"$FileVersion\",\"$PieBinary\"" >> PIDRecords.txt
					#Duplicate entry was found, display parameters
					else
						if [ $DEBUG -gt 0 ] ; then
							duplicate_entry
						fi
					fi
					#Check for system-wide ASLR
					if [[ "$SysASLR" = 'TRUE' ]] && [[ "$PieBinary" = 'TRUE' ]] && [[ "$PieProcess" = 'TRUE' ]] ; then
						ASLR='TRUE'
					else
						ASLR='FALSE'
					fi
					
					if [ $DEBUG -gt 0 ] ; then
						echo -e "\tASLR: |$ASLR|\n\tSysASLR: |$SysASLR|\n\tPieBinary: |$PieBinary|\n\tPieProcess: |$PieProcess|"
					fi
					#Print Data To File
					echo "\"$ProcessName\",\"$PID\",\"$ProcessPath\",\"$Protocol\",\"$LocalAddress\",\"$LocalPort\",\"$LocalPortName\",\"$RemoteAddress\",\"$RemotePort\",\"$RemoteHostName\",\"$RemotePortName\",\"$State\",\"$ProductName\",\"$FileDescription\",\"$FileVersion\",\"$Company\",\"$ProcessCreatedOn\",\"$UserName\",\"$ProcessServices\",\"$ProcessAttributes\",\"$DetectionTime\",\"$ARCH\",\"$ASLR\",\"$DEP\",\"$RELRO\",\"$StackCanary\"" >> BinaryAnalysis.csv
					#reset counter
					counter=1
#					#Reset duplicate entry flag
#					DuplicateEntry='FALSE'
					if [ $DEBUG -gt 0 ] ; then
						echo -e "\nDefault tool output:"
					fi
					echo -e "ProcessName: $ProcessName\tPID: $PID\tProcessPath: $ProcessPath"
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
	#Clear out PIDRecords.txt
	echo -n "\"0,Unknown,,,,ScanError,ScanError,ScanError,ScanError,ScanError,,,ScanError\"
" > PIDRecords.txt
	#Reset BinaryAnalysis.csv to header
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

#Check for debug output type
	case "$1" in 
		#Displays function names, all primary vars, and intermediary vars used to build primary ones
		--verbose)
			DEBUG=2
			echo "verbose"
		;;
		#Displays function names and all primary vars
		--debug)
			DEBUG=1
			echo "debug"
		;;
		'')
		#Default output
			DEBUG=0
			echo "default"
		;;
		--help)
			echo -e "Options:\n\t--verbose\n\t\tDisplays function names, primary vars, and vars used to build primary vars"
			echo -e "\t--debug\n\t\tDisplays function names and primary vars"
		;;
		*)
			echo -e "Invalid Parameter"
			echo -e "Options:\n\t--verbose\n\t\tDisplays function names, primary vars, and vars used to build primary vars"
			echo -e "\t--debug\n\t\tDisplays function names and primary vars"
	esac

#include source files for function calls
DIR="${BASH_SOURCE%/*}"
. "$DIR/deps/checksec/checksec.sh"
#start scraper
aha_wrapper
