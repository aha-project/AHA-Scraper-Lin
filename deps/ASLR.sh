PID=$1
DEBUG=$2
echo "DEBUG = $DEBUG" 
echo "PID = $PID"
if [ $DEBUG > 0 ] ; then
	echo "ASLR()"
fi
#Check if PID is empty
if [ "$PID" == '0' ] ; then
	SysASLR="ScanError"
	return
fi

if cat /proc/$PID/status 2> /dev/null | grep -q 'PaX:'; then
	echo ": "
	if cat /proc/1/status 2> /dev/null | grep 'PaX:' | grep -q 'R'; then
		echo 'ASLR enabled'
	else
		echo 'ASLR disabled'
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
if [ $DEBUG > 0 ] ; then
	echo -n "$SysASLR"
fi
