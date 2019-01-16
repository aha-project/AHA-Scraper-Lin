#!/bin/bash
DEBUG=2
BinaryArray=''		#Holds array of binary names
UniqueBinary='TRUE'
PID=1816
ProcessName=1
ProcessPath=1
ProcessCreatedOn=1
UserName=1
PieProcess=1
SysASLR=1
RELRO=1
StackCanary=1
DEP=1
FileDescription=1
FileVersion=1
PieBinary=1
var=1
DuplicateEntry=1

testfunc() {
	if [ $var = 1 ] ; then
		echo "TRUE"
	fi
}

testf() {
	local dup=$(testfunc)
	if [[ "$dup" = 'TRUE' ]] ; then
		echo "TRUE"
	else
		echo "FALSE"
	fi
}


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
		echo "line: |$line|"

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
						echo "Inner DuplicateEntry: $dup
						duplicate entry found: $PID
						"
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
}


#Link to checksec file so we can call functions from there
DIR="${BASH_SOURCE%/*}"
. "$DIR/deps/checksec/checksec.sh"

echo "PID: $PID"
testf
