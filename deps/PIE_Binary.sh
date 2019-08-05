#Checks binary for PIE support, implies ASLR is enabled for the binary
ProcessPath=$1
DEBUG=$2
echo "DEBUG = $DEBUG" 
echo "PID = $PID"
#Check for PIE type
type=$(readelf -h "${ProcessPath}" | grep 'Type:')
if [ "$type" = *'EXEC'* ] ; then
	PieBinary='FALSE'
#If ELF is a dynamic shared object
elif [ "$type" = *'DYN'* ] ; then
	PieBinary='TRUE'
fi
#Echo result back
echo -n $PieBinary
