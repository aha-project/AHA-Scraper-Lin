import sys, os, socket, time, json, io
from io import open
from datetime import datetime
from subprocess import Popen, PIPE

#TODO: fix user control over debugging
#Debug variable, controls test printing for each function output
#If Debug=4, output needed input
#If Debug=5, input needed input from a debug=4 run. !Extra param needed for file name!
VERSION="19.8.2"
DEBUG=0
SysASLR = ''
ProcASLR = ''
PIE_binary = ''
PIE_process = ''
ScanTimeString = ''
#Holds netstat output with Addresses resolved
netstat_names = []
#Contains ordered entries of processes
printList = []
#Contains all popen commands if debug=4/5
debug_recall = []
#Holds info for current proc
CurrentProc = { 'ProcessName' : '', 'PID' : 0, 'ProcessPath' : '', 'Protocol' : '', 'LocalAddress' : '', 'LocalPort' : '', 'LocalHostName' : '', 'LocalPortName' : '', 'RemoteAddress' : '', 'RemotePort' : '', 'RemoteHostName' : '', 'RemotePortName' : '', 'State' : '', 'ProductName' : '', 'FileDescription' : '', 'FileVersion' : '', 'Company' : '', 'ProcessCreatedOn' : '', 'UserName' : '', 'ProcessServices' : '', 'ProcessAttributes' : '', 'DetectionTime' : '', 'ARCH' : '', 'ASLR' : '', 'DEP' : '', 'RELRO' : '', 'StackCanary' : '', 'INODE' : '', 'CLIArguments': ''}

#holds format for netstat parsing, acts like a switch statement
netstat_var = {0: 'Protocol', 1: 'LocalAddress', 2: 'LocalPort', 3: 'RemoteAddress', 4: 'RemotePort', 5: 'State', 6: 'UID', 7: 'INODE', 8: 'PID', 9: 'ProcessName' }
domain_var = {0: 'Protocol', 1: 'State', 2: 'INODE', 3: 'PID', 4: 'ProcessPath'}
#dictionary that holds entries for PIDs
#   access specific values by: procDict[pid][varName]
procDict = {}
#-----------------------Helper Functions ----------------------------------------


#Wrap around every Popen, not popen. Should have stdout and stderr
#Ex: Popen_Wrapper(Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE))
def Popen_Wrapper(process):
  global debug_recall
  (o, e) = process.communicate()
  if DEBUG == 5:
    #Nothing left, probably a older version debug recall
    if len(debug_recall) == 0:
      return ('', '')
    #Get stdout
    o = str(debug_recall[0])
    debug_recall = debug_recall[1:]
    if len(debug_recall) == 0:
      return (o, '')
    #Get stderr
    e = str(debug_recall[0])
    debug_recall = debug_recall[1:]
  else:
    if DEBUG == 4:
      debug_recall.append(o)
      debug_recall.append(e)
  return (o, e)


#Converts the input date format and returns the preferred output date format
#Learned: How to only show selected columns of 'ps' , how to grep for PID using ps output, converting date time formats, tokenizing (I had a few iterations of this function)
def Convert_Date(oldformat):
  if(DEBUG > 0):
    print('Convert_Date()------------------------------------')
  datetimeobject = datetime.strptime(oldformat, '%Y-%m-%d %H:%M:%S.%f')
  newformat = datetimeobject.strftime('%m/%d/%Y %H:%M')
  return newformat

#Gets the current date / time and formats it to the preferred output
def Detection_Time():
  global ScanTimeString
  if(DEBUG > 0):
    print('Detection_Time()------------------------------------')
  detectionTime, e = Popen_Wrapper(Popen("date '+%m/%d/%Y %H:%M'", shell=True, stdout=PIPE, stderr=PIPE))
  ScanTimeString = Clean_String(detectionTime)
  if(DEBUG > 0):
    print('Time Detected: '+CurrentProc['DetectionTime'])

#Removes duplicate spaces, trailing whitespace, and newline chars
# and returns result
def Clean_String(s):
  #Remove trailing newline and whitespaces
  s.rstrip()
  #Remove extra whtiespace
  s = ' '.join(s.split())
  return s

#Accepts a string value and checks if the string is an integer
#Returns a boolean value
def Is_Int(s):
  try: 
    int(s)
    return True
  except ValueError as e:
    return False


#-----------------------Auxhilary Functions ------------------------------
#Creates initial dictionary entry '0'
def Init_Dict():
  procDict[0] = {}
  procDict[0]['PID'] = 0
  procDict[0]['ProcessName'] = 'unknown'
  procDict[0]['ProcessPath'] = ''
  procDict[0]['State'] = str(CurrentProc['State'])
  procDict[0]['ProductName'] = ''
  procDict[0]['FileDescription'] = ''
  procDict[0]['FileVersion'] = ''
  procDict[0]['Company'] = ''
  procDict[0]['ProcessCreatedOn'] = str(CurrentProc['ProcessCreatedOn'])
  procDict[0]['UserName'] = ''
  procDict[0]['ProcessServices'] = ''
  procDict[0]['ProcessAttributes'] = ''
  procDict[0]['DetectionTime'] = str(CurrentProc['DetectionTime'])
  procDict[0]['ARCH'] = 'ScanError'
  procDict[0]['ASLR'] = 'ScanError'
  procDict[0]['PIE-Binary'] = 'ScanError'
  procDict[0]['DEP'] = 'ScanError'
  procDict[0]['RELRO'] = 'ScanError'
  procDict[0]['StackCanary'] = 'ScanError'
  procDict[0]['CLIArguments'] = ''

#Checks if the process path is empty and sets values appropriately
def Proc_Check(path):
  if(DEBUG > 0):
    print("Proc_Check() |"+str(path)+'|')
  if (path == ''):
    CurrentProc['RELRO']='ScanError'
    CurrentProc['StackCanary']='ScanError'
    CurrentProc['DEP']='ScanError'
  else:
    RELRO(path)
    Stack_Canary(path)
    DEP_NX_Enabled(path)

#Gets and sets the current Architecture
#TODO: support other architectures
def Architecture(pid):
  if(DEBUG > 0):
    print('Architecture() PID: |'+str(pid)+'|------------------------------------')
  #Check for valid pid
  if(pid <= 0):
    CurrentProc['ARCH']= 'ScanError'
    return
  ARCH, e = Popen_Wrapper(Popen("file -L /proc/"+str(pid)+'/exe', shell=True, stdout=PIPE, stderr=PIPE))
  if len(e) > 0:
    sys.exit('ERROR: ' + e)
  ARCH = Clean_String(ARCH)
  ARCH = ARCH.split(',')
  ARCH = ARCH[1] if len(ARCH) > 1 else ''
  #Check if we need to standardize the architecture
  if(('x86-64' in ARCH) or ('AMD64' in ARCH)):
    ARCH = 'AMD64'
  if len(ARCH) == 0:
    #Check if kernel sub process
    if len(CurrentProc['ProcessName']) > 0 and CurrentProc['ProcessName'][0] == '[':
      ARCH, e = Popen_Wrapper(Popen('uname -a', shell=True, stdout=PIPE, stderr=PIPE))
      if(('x86-64' in ARCH) or ('x86_64' in ARCH) or ('AMD64' in ARCH)):
        ARCH = 'AMD64'
      else:
        ARCH = 'ScanError'
    else:
      ARCH = 'ScanError'
  if(DEBUG > 1):
    print('ARCH: |'+str(ARCH)+'|')
  CurrentProc['ARCH']=ARCH

#Accepts a CurrentProc structure and inserts it into the ordered printList, ordered by PID
def Insert_Print_List(curProc):
  #define a counter variable
  i = 0
  #capture pid for current proc:
  pid = int(curProc['PID'])

  if(DEBUG > 0):
      print('Insert_Print_List() with PID |'+str(pid)+'|------------------------------------')
  if(DEBUG > 2):
    print('currentProc: ')
    print(curProc)

  #Check if the list is empty
  if (len(printList) == 0):
    if(DEBUG > 2):
      print('printList was empty')
    printList.insert(0,curProc)
    return
  
  #Find where to insert within the list
  for x in printList:
    #If we are less than the current index, insert
    if (pid < int(x['PID'])):
      break
    else:
      i +=1
  printList.insert(i, curProc)
  if(DEBUG > 2):
    print('Inserting PID: '+str(pid)+' into printList at index: '+str(i))
    print("Resulting List: " +str(printList))
#Adds a unique entry to the dictionary based on PID, must be int
def Add_Entry(pid):
  #Make sure int
  if type(pid) != type(0):
    sys.exit('ERROR!! Add_entry requires int type for pid')
  #temporary variable to hold proc information and create new memory for entries in printList
  #NOTE: cannot simply insert CurrentProc entry to printList sicne the memory address is the same
  #As such, inserting CurrentProc multiple times and modifying results in all entries being changed
  #To the latest data stored in CurrentProc
  curProc = { 'ProcessName' : '', 'PID' : 0, 'ProcessPath' : '', 'Protocol' : '', 'LocalAddress' : '', 'LocalPort' : '', 'LocalHostName' : '', 'LocalPortName' : '', 'RemoteAddress' : '', 'RemotePort' : '', 'RemoteHostName' : '', 'RemotePortName' : '', 'State' : '', 'ProductName' : '', 'FileDescription' : '', 'FileVersion' : '', 'Company' : '', 'ProcessCreatedOn' : '', 'UserName' : '', 'ProcessServices' : '', 'ProcessAttributes' : '', 'DetectionTime' : '', 'ARCH' : '', 'ASLR' : '', 'DEP' : '', 'RELRO' : '', 'StackCanary' : '', 'INODE' : '', 'CLIArguments': ''}
  
  #Check if IPv6 Protocol, parse out '6'
  if('6' in CurrentProc['Protocol']):
    if('tcp' in CurrentProc['Protocol']):
      CurrentProc['Protocol'] = 'tcp'
    else:
      CurrentProc['Protocol'] = 'udp'
  
  #Set entry to new dictionary
  procDict[pid] = {}
  if(DEBUG > 0):
    print('Add_Entry() PID: |'+str(pid)+'|------------------------------------')
  #Store entry in procDict for duplicate entries
  procDict[pid]['PID'] = str(CurrentProc['PID'])
  procDict[pid]['ProcessName'] = str(CurrentProc['ProcessName'])
  procDict[pid]['ProcessPath'] = str(CurrentProc['ProcessPath'])
  procDict[pid]['ProcessCreatedOn'] = str(CurrentProc['ProcessCreatedOn'])
  procDict[pid]['UserName'] = str(CurrentProc['UserName'])
  procDict[pid]['ProcessServices'] = str(CurrentProc['ProcessServices'])
  procDict[pid]['ProductName'] = str(CurrentProc['ProductName'])
  procDict[pid]['ProcessAttributes'] = str(CurrentProc['ProcessAttributes'])
  procDict[pid]['FileDescription'] = str(CurrentProc['FileDescription'])
  procDict[pid]['FileVersion'] = str(CurrentProc['FileVersion'])
  procDict[pid]['Company'] = str(CurrentProc['Company'])
  procDict[pid]['ARCH'] = str(CurrentProc['ARCH'])
  procDict[pid]['ASLR'] = str(CurrentProc['ASLR'])
  procDict[pid]['PIE-Binary'] = PIE_binary
  procDict[pid]['DEP'] = str(CurrentProc['DEP'])
  procDict[pid]['RELRO'] = str(CurrentProc['RELRO'])
  procDict[pid]['StackCanary'] = str(CurrentProc['StackCanary'])
  procDict[pid]['CLIArguments'] = ''
  
  #NOTE: Had to build string manually; iteration over the object didn't produce expected order
  #Create string to print to to file:
  curProc['ProcessName'] =  CurrentProc['ProcessName']
  curProc['PID'] =  CurrentProc['PID']
  curProc['ProcessPath'] =  CurrentProc['ProcessPath']
  curProc['Protocol'] =  CurrentProc['Protocol']
  curProc['LocalAddress'] =  CurrentProc['LocalAddress']
  curProc['LocalPort'] =  str(CurrentProc['LocalPort'])
  curProc['LocalHostName'] =  CurrentProc['LocalHostName']
  curProc['LocalPortName'] =  CurrentProc['LocalPortName']
  curProc['RemoteAddress'] =  CurrentProc['RemoteAddress']
  curProc['RemotePort'] =  CurrentProc['RemotePort']
  curProc['RemoteHostName'] =  CurrentProc['RemoteHostName']
  curProc['RemotePortName'] =  CurrentProc['RemotePortName']
  curProc['State'] =  CurrentProc['State']
  curProc['ProductName'] =  CurrentProc['ProductName']
  curProc['FileDescription'] =  CurrentProc['FileDescription']
  curProc['FileVersion'] =  CurrentProc['FileVersion']
  curProc['Company'] =  CurrentProc['Company']
  curProc['ProcessCreatedOn'] =  CurrentProc['ProcessCreatedOn']
  curProc['UserName'] =  CurrentProc['UserName']
  curProc['ProcessServices'] =  CurrentProc['ProcessServices']
  curProc['ProcessAttributes'] =  CurrentProc['ProcessAttributes']
  curProc['DetectionTime'] =  ScanTimeString
  curProc['ARCH'] =  CurrentProc['ARCH']
  curProc['PIE-Binary'] = procDict[pid]['PIE-Binary']
  curProc['ASLR'] =  CurrentProc['ASLR']
  curProc['DEP'] =  CurrentProc['DEP']
  curProc['RELRO'] =  CurrentProc['RELRO']
  curProc['StackCanary'] =  CurrentProc['StackCanary']
  curProc['CLIArguments'] = CurrentProc['CLIArguments']
  
  #Insert entry into our printList
  Insert_Print_List(curProc)

#A duplicate entry has been detected, do not scan again and reprint info to file
#   How to acces entry variables: procDict[pid][varName]
def Duplicate_Entry(pid):
  #Make sure int
  if type(pid) != type(0):
    sys.exit('ERROR!! Duplicate requires pid to be int type.')
  if (DEBUG > 0):
    print('Duplicate_Entry() |'+str(pid)+'|------------------------------------')
  #Call architecture function
  Architecture(pid)
  #Check if IPv6 Protocol
  if('6' in CurrentProc['Protocol']):
    if('tcp' in CurrentProc['Protocol']):
      CurrentProc['Protocol'] = 'tcp'
    else:
      CurrentProc['Protocol'] = 'udp'
  
  #temporary variable to hold proc information
  curProc = { 'ProcessName' : '', 'PID' : 0, 'ProcessPath' : '', 'Protocol' : '', 'LocalAddress' : '', 'LocalPort' : '', 'LocalHostName' : '', 'LocalPortName' : '', 'RemoteAddress' : '', 'RemotePort' : '', 'RemoteHostName' : '', 'RemotePortName' : '', 'State' : '', 'ProductName' : '', 'FileDescription' : '', 'FileVersion' : '', 'Company' : '', 'ProcessCreatedOn' : '', 'UserName' : '', 'ProcessServices' : '', 'ProcessAttributes' : '', 'DetectionTime' : '', 'ARCH' : '', 'ASLR' : '', 'DEP' : '', 'RELRO' : '', 'StackCanary' : '', 'INODE' : '', 'CLIArguments': ''}
  #NOTE: Had to build string manually; iteration over the object didn't produce expected order
  #Create string to print to to file:
  curProc['ProcessName'] =  procDict[pid]['ProcessName']
  curProc['PID'] =  procDict[pid]['PID']
  curProc['ProcessPath'] =  procDict[pid]['ProcessPath']
  curProc['Protocol'] =  CurrentProc['Protocol']
  curProc['LocalAddress'] =  CurrentProc['LocalAddress']
  curProc['LocalPort'] =  str(CurrentProc['LocalPort'])
  curProc['LocalHostName'] =  CurrentProc['LocalHostName']
  curProc['LocalPortName'] =  CurrentProc['LocalPortName']
  curProc['RemoteAddress'] =  CurrentProc['RemoteAddress']
  curProc['RemotePort'] =  CurrentProc['RemotePort']
  curProc['RemoteHostName'] =  CurrentProc['RemoteHostName']
  curProc['RemotePortName'] =  CurrentProc['RemotePortName']
  curProc['State'] =  CurrentProc['State']
  curProc['ProductName'] =  procDict[pid]['ProductName']
  curProc['FileDescription'] =  procDict[pid]['FileDescription']
  curProc['FileVersion'] =  procDict[pid]['FileVersion']
  curProc['Company'] =  procDict[pid]['Company']
  curProc['ProcessCreatedOn'] =  procDict[pid]['ProcessCreatedOn']
  curProc['UserName'] =  procDict[pid]['UserName']
  curProc['ProcessServices'] =  procDict[pid]['ProcessServices']
  curProc['ProcessAttributes'] =  procDict[pid]['ProcessAttributes']
  curProc['DetectionTime'] =  ScanTimeString
  curProc['ARCH'] =  CurrentProc['ARCH']
  curProc['ASLR'] =  procDict[pid]['ASLR']
  curProc['PIE-Binary'] = procDict[pid]['PIE-Binary']
  curProc['DEP'] =  procDict[pid]['DEP']
  curProc['RELRO'] =  procDict[pid]['RELRO']
  curProc['StackCanary'] =  procDict[pid]['StackCanary']
  curProc['CLIArguments'] = procDict[pid]['CLIArguments']
  #Insert curProc data into our printList
  Insert_Print_List(curProc)

#If debug mode is 4 then it writes recall.
def Write_If_Debug(fileName):
  if DEBUG is 4:
    print('Writing debug to %s' % fileName)
    with io.open(fileName, 'w', encoding='utf8') as jsonFile:
      raw = json.dumps({'data': debug_recall, 'version': VERSION}, ensure_ascii=True)
      jsonFile.write(unicode(raw))

#If debug mode is 5 then it reads debug into recall.
#No error check is done to know if it is successful
def Read_Debug_Recall(fileName):
  global debug_recall
  if DEBUG is 5:
    f = open(fileName, 'r')
    raw = f.read()
    debug_recall = json.loads(raw)['data']
    print('Load size: %d' % len(debug_recall))

#Writes the information to a CSV to be used later in scoring
def Write_To_File():
  if (DEBUG > 0):
    print("Write_To_File()------------------------------------------------------------------------")
  #Open CSV to append values
  f = open('BinaryAnalysis.csv', "a")
  #Iterate over printList and print all contents to file
  for x in printList:
    #NOTE: Had to build string manually; iteration over the object didn't produce expected order
    cur = "\""+x['ProcessName']+"\",\""+str(x['PID'])+"\",\""+x['ProcessPath']+"\",\""+x['Protocol']+"\",\""+x['LocalAddress']+"\",\""+str(x['LocalPort'])+"\",\""+x['LocalHostName']+"\",\""+x['LocalPortName']+"\",\""+x['RemoteAddress']+"\",\""+x['RemotePort']+"\",\""+x['RemoteHostName']+"\",\""+x['RemotePortName']+"\",\""+x['State']+"\",\""+x['ProductName']+"\",\""+x['FileDescription']+"\",\""+x['FileVersion']+"\",\""+x['Company']+"\",\""+x['ProcessCreatedOn']+"\",\""+x['UserName']+"\",\""+x['ProcessServices']+"\",\""+x['ProcessAttributes']+"\",\""+x['DetectionTime']+"\",\""+x['ARCH']+"\",\""+x['ASLR']+"\",\""+x['PIE-Binary']+"\",\""+x['DEP']+"\",\""+x['RELRO']+"\",\""+x['StackCanary']+"\",\""+x['CLIArguments']+"\""
    cur = cur.replace('\n', '')
    if (DEBUG > 2):
      print("Outputting to CSV: |"+cur+"|")
    #Write data to file
    f.write(cur.decode('utf-8'))
    #Write newline to file
    f.write('\n'.decode('utf-8'))

  #Note: must encode in utf-8 to write string to CSV
  #ensure file is closed
  f.close()

def Reset_Values():
  global SysASLR, ProcASLR, PIE_binary, PIE_process, CurrentProc
  #Reset vars that determine ASLR
  SysASLR = 'ScanError'
  ProcASLR = 'ScanError'
  PIE_binary = 'ScanError'
  PIE_process = 'ScanError'
  #Reset CurrentProc values
  CurrentProc = { 'ProcessName' : '', 'PID' : 0, 'ProcessPath' : '', 'Protocol' : '', 'LocalAddress' : '', 'LocalPort' : '', 'LocalHostName' : '', 'LocalPortName' : '', 'RemoteAddress' : '', 'RemotePort' : '', 'RemoteHostName' : '', 'RemotePortName' : '', 'State' : '', 'ProductName' : '', 'FileDescription' : '', 'FileVersion' : '', 'Company' : '', 'ProcessCreatedOn' : '', 'UserName' : '', 'ProcessServices' : '', 'ProcessAttributes' : '', 'DetectionTime' : '', 'ARCH' : 'ScanError', 'ASLR' : 'ScanError', 'DEP' : 'ScanError', 'RELRO' : 'ScanError', 'StackCanary' : 'ScanError', 'INODE' : '', 'CLIArguments': '', 'PIE-Binary': 'ScanError'}

#-----------------------Binary Analysis Functions ------------------------------
#Calculates when the process was created and converts the date into scoring format
# sets CurrentProc[ProcessCreatedOn]
def Proc_Created_On(pid):
  if(DEBUG > 0):
    print('Proc_Created_On() |'+str(pid)+'|------------------------------------')
  #Get the amount of time the process has been up, in seconds
  elapsed, e = Popen_Wrapper(Popen('ps -eo pid,etimes | grep -w '+str(pid), shell=True, 
                             stdout=PIPE, stderr=PIPE))
  #Remove extra whitespaces and trailing whitespace
  elapsed = ' '.join(str(elapsed).split())
  #split into array
  elapsed = elapsed.split(' ')
  #assign elapsed time (first element is the PID used to ID the time)
  if len(elapsed) > 1:
    elapsed = elapsed[1]
    if(DEBUG >1):
      print('Elapsed time in seconds: |'+elapsed+'|')
    #Convert the elapsed time into a datetime object
    date = datetime.fromtimestamp(time.time() - float(elapsed))
    #Convert datetime to format we want
    date = Convert_Date(str(date))
    if(DEBUG > 0):
      print('|'+str(date)+'|')
  else:
    date = ''
  CurrentProc['ProcessCreatedOn'] = date

#Takes in a file path then returns the description and version of the file
#sets     CurrentProc['FileDescription'] && CurrentProc['FileVersion']
def File_Info():
  path = CurrentProc['ProcessPath']
  if(DEBUG > 0):
    print('File_Info() |'+path+'|------------------------------------')
  #Check for valid path
  if(path == ''):
    CurrentProc['FileVersion']= ''
    CurrentProc['FileDescription'] = ''
    return
  #Get file header and filter for version
  version, e = Popen_Wrapper(Popen('readelf -h \''+path+"\' | grep -w 'Version' ", shell=True,
                                   stdout=PIPE, stderr=PIPE))
  #Get brief description of file
  description, e2 = Popen_Wrapper(Popen('file -b \''+path+"\'", shell=True, stdout=PIPE,
                                        stderr=PIPE))
  #Clean version string
  version = Clean_String(str(version))
  #Clean description string
  description = Clean_String(str(description))
  if(DEBUG > 0):
    print('Description: |'+str(description)+'|')
    print('Version: |'+str(version)+'|')
  #Split version into list to pull out version info
  version = version.split(':')
  #Split description into list to pull out description info
  description = description.split(',')
  
  #Verify that the proc exists
  if('Error:' in version):
    if(DEBUG > 0):
      print('ERROR: '+path+' does not exist in this context')
  else:
    CurrentProc['FileVersion'] = version[1] if len(version) > 1 else ''
    CurrentProc['FileDescription'] = description[0] if len(description) > 0 else ''
    if(DEBUG > 0):
      print('File Description: |'+CurrentProc['FileDescription']+'| File Version: |'+CurrentProc['FileVersion']+'|')

#Accepts a process pid, gets and sets the path of the given process' binary
#sets CurrentProc['ProcessPath']
#Learned: Location of process binaries, how to select specific output of tokenized string
def Proc_Path(pid):
  if(DEBUG > 0):
    print('Proc_Path() |'+str(pid)+'|------------------------------------')
    print(CurrentProc['ProcessPath'])
  #Check for valid pid
  if(pid == 0):
    ProcessPath=''
    return
  #Grab file info
  if(DEBUG > 1):
    print("Command: |"+'readlink -f '+'/proc/'+str(pid)+'/exe|')
  path, e = Popen_Wrapper(Popen('readlink -f '+'/proc/'+str(pid)+'/exe', shell=True, stdout=PIPE,
                                stderr=PIPE))
  #Fixes (deleted) part at end that is sometimes there
  path = path.replace('\n', '').strip()
  if(DEBUG > 2):
    print('Path returned from readlink -f: |'+path+'|')
  #Check for broken symbolic link
  if('deleted' in path):
    path = path.split()
    path = path[0] if len(path) > 0 else ''
  #Grab last element, which is the file description
  CurrentProc['ProcessPath'] = path
  if(DEBUG > 1):
    print('ProcessPath: |'+CurrentProc['ProcessPath']+'|')

#sets CurrentProc['ProcessName']
#Uses the currently set ProcessPath and parses out the ProcessName
def Proc_Name():
  name = str(CurrentProc['ProcessPath'])
  if '/' in name:
    name = name.split('/')
    CurrentProc['ProcessName'] = name[len(name)-1]
  else:
    CurrentProc['ProcessName'] = name

#Takes in a PID and sets the username
def Proc_User_Name(pid):
  if(DEBUG > 0):
    print('Proc_User_Name() |'+str(pid)+'|------------------------------------')
  #Find username associated with pid
  #user:32 sets username column to 32 chars to avoid truncated names e.g. 'usernam+'
  name, e = Popen_Wrapper(Popen('ps axo user:32,pid | grep '+str(pid), shell=True, stdout=PIPE, 
                                stderr=PIPE))
  #remove extra spaces
  name = ' '.join(name.split())
  #Convert to array
  name = name.split(' ')
  #Assign ProcessName
  CurrentProc['UserName']=name[0]
  if(DEBUG > 1):
    print('UserName: |'+ CurrentProc['UserName']+'|')

#-----------------------Process Analysis Functions ----------------------_------

#Sets the host and port names for local and remote based on inode number
def Host_Port_Name(inode):
  #Convert to string to reduce processing
  inode = str(inode)
  #Holds output line we want
  line = ''
  #Used to skip logic that sets variables
  found = 0
  if(DEBUG > 0):
    print('Host_Port_Name() for: |'+inode+'|------------------------------------')
  for x in netstat_names:
    if (inode in x):
      if(DEBUG > 1):
        print('Found a matchng line')
      line = x
      #set found to true
      found = 1
      break
  #return if no match was found
  if(found == 0):
    if(DEBUG > 1):
      print('No match for |'+inode+'| was found')
    return
  #Remove extra whitespace and trailing newline chars-
  line = Clean_String(line)
  if(DEBUG > 1):
    print('Line containing '+inode+': |'+line+'|')
  #split line into list
  line = line.split(' ')
  #Capture local information
  local = line[3]
  #Split into localHostName localPortName
  local = local.split(':')
  #Check if we're parsing abbreviated IPv6, not a hostname
  if(len(local) > 2):
    local[0] = ''
    local[1] = local[len(local)-1]
  #Capture remote information
  remote = line[4]
  #Split into remoteHostName remotePortName
  remote = remote.split(':')
  if(len(remote) > 2):
    remote[0] = ''
    remote[1] = remote[len(remote)-1]
  if(DEBUG > 2):
    print('local output: |'+str(local)+'|')
    print('remote output: |'+str(remote)+'|')
  
  #set local host name and port name
  CurrentProc['LocalHostName'] = local[0]
  #Check if port name is resolved
  if(Is_Int(local[1])):
    CurrentProc['LocalPortName'] = ''
  else:
    CurrentProc['LocalPortName'] = local[1]
  #If connection is not established, then names aren't resolved
  if('ESTABLISHED' in line):
    #set remote host name and port name
    CurrentProc['RemoteHostName'] = remote[0]
    #Check if port name is resolved
    if(Is_Int(remote[1])):
      CurrentProc['RemotePortName'] = ''
    else:
      CurrentProc['RemotePortName'] = remote[1]
  else:
    CurrentProc['RemoteHostName'] = ''
    CurrentProc['RemotePortName'] = ''

  if(DEBUG > 1):
    print('LocalHostName: |'+CurrentProc['LocalHostName']+'|  LocalPortName: |'+CurrentProc['LocalPortName']+'|')
    print('RemoteHostName: |'+CurrentProc['RemoteHostName']+'|  RemotePortName: |'+CurrentProc['RemotePortName']+'|')

#----------------------checksec functions
#NOTE: The final value of ASLR is a combination of three sub-components to ASLR
#   SysASLR, PieBinary, and PieProcess must be true to set overall ASLR to true
#Source: checksec.sh
#Detects if ASLR is enabled for the system
#TODO: Update function to use python, not call the script
#NOTE: Calling script may be the best way to evaluate ASLR
def ASLR(pid):
  global SysASLR
  if(DEBUG > 0):
    print('Sys_ASLR() |'+str(pid)+'|------------------------------------')
  output, e = Popen_Wrapper(Popen("sysctl -a 2> /dev/null | grep 'kernel.randomize_va_space = '", shell=True,
                                  stdout=PIPE, stderr=PIPE))
  if('0' in output):
    SysASLR = 'DISABLED'
  elif('1' in output):
    SysASLR = 'PARTIAL'
  elif('2' in output):
    SysASLR = 'TRUE'
  else:
    SysASLR = 'ScanError'

#Check binary for PIE support, which implies that ASLR is enabled
#modified from checksec.sh
def PIE_Binary(path):
  global PIE_binary
  if(DEBUG > 0):
    print("PIE_Binary() |"+path+'|------------------------------------')
  #Check if PID is valid, return set to ScanError if not
  if(path==''):
    PIE_binary = 'ScanError'
    if(DEBUG > 0):
      print('PIE_binary: '+PIE_binary)
    return
  #Get binary information using readelf and grep for the Type
  output, e = Popen_Wrapper(Popen('readelf -h \''+path+"\' | grep 'Type:'", shell=True, stdout=PIPE,
                                  stderr=PIPE))
  output = Clean_String(str(output))
  #Check what type the binary is
  if('EXEC' in output):
    PIE_binary = 'FALSE'
  elif("DYN" in str(output)):
    PIE_binary = 'TRUE'
  else:
    PIE_binary = 'ScanError'
  if(DEBUG > 0):
    print('PIE_binary: '+str(PIE_binary))

#Evaluates if the process supports PIE and saves the result
#modified from checksec.sh
def PIE_Process(pid):
  global PIE_process
  if(DEBUG > 0):
    print('PIE_Process(): |'+str(pid)+'|------------------------------------')
  #Check if PID is valid, return set to ScanError if not
  if(pid==0):
    PIE_process = 'ScanError'
    if(DEBUG > 0):
      print('PIE_process: '+PIE_process)
    return
  #Get binary information using readelf and grep for the Type
  output, e = Popen_Wrapper(Popen('readelf -h /proc/'+str(pid)+"/exe | grep 'Type:'", shell=True, stdout=PIPE,
                               stderr=PIPE))
  output = Clean_String(str(output))
  #Check what type the binary is
  if('EXEC' in output):
    PIE_process = 'FALSE'
  elif("DYN" in str(output)):
    PIE_process = 'TRUE'
  else:
    PIE_process = 'ScanError'
  if(DEBUG > 0):
    print('PIE_process: '+str(PIE_process))

#Check for execute permissions being enabled on the binary
#modified from checksec.sh
def DEP_NX_Enabled(path):
  if(DEBUG > 0):
    print("DEP_NX_Enabled() |"+path+'|------------------------------------')
  #Check if PID is valid, return set to ScanError if not
  if(path==''):
    CurrentProc['DEP'] = 'ScanError'
    if(DEBUG > 0):
      print('DEP: '+CurrentProc['DEP'])
    return
  #Get file headers and find info on GNU_STACK, include next matching line
  output, e = Popen_Wrapper(Popen('readelf -l \''+path+"\' | grep -A 1 'GNU_STACK'", shell=True,
                                  stdout=PIPE, stderr=PIPE))
  output = Clean_String(str(output))
  #Show line matching GNU_STACK
  if(DEBUG > 2):
    print(output)
  #Check what type the binary is
  if('RWE' in output):
    CurrentProc['DEP'] = 'TRUE'
  else:
    CurrentProc['DEP'] = 'FALSE'
  if(DEBUG > 0):
    print('DEP: '+CurrentProc['DEP'])

#Checks for RELRO support and saves the result
#modified from checksec.sh
def RELRO(path):
  if(DEBUG > 0):
    print("RELRO() |"+path+'|------------------------------------')
  #Check if PID is valid, return set to ScanError if not
  if(path==''):
    CurrentProc['RELRO'] = 'ScanError'
    if(DEBUG > 0):
      print('RELRO: '+CurrentProc['RELRO'])
    return
  
  #Get program headers for input proc path, read all the output
  output, e = Popen_Wrapper(Popen('readelf -l \''+path+"\'", shell=True, stdout=PIPE, stderr=PIPE))
  #Check if we have permissions to read program header inforamation
  if('Program Headers' in output):
    #Check for RELRO support
    if('GNU_RELRO' in output):
      #Get info on what type "t" of RELRO is supported from the dynamic section
      t, e = Popen_Wrapper(Popen('readelf -d \''+path+"\'", shell=True, stdout=PIPE, stderr=PIPE))
      #Clean string of garbage chars
      t = Clean_String(str(t))
      if('BIND_NOW'):
        CurrentProc['RELRO']='TRUE'
      else:
        CurrentProc['RELRO']='PARTIAL'
    else:
      CurrentProc['RELRO']='FALSE'
      if(DEBUG > 0):
        print("No RELRO support found")
  else:
    CurrentProc['RELRO']='ScanError'
    if(DEBUG > 0):
      print("Cannot read Program Headers. Please run as root")
  if(DEBUG > 0):
    print('RELRO: '+CurrentProc['RELRO'])

#Checks for stack canary support and saves the result
#modified from checksec.sh
def Stack_Canary(path):
  if(DEBUG > 0):
    print("RELRO() |"+path+'|------------------------------------')
  #Check if PID is valid, return set to ScanError if not
  if(path==''):
    CurrentProc['RELRO'] = 'ScanError'
    if(DEBUG > 0):
      print('RELRO: '+CurrentProc['RELRO'])
    return
  #Get symbol table for input path
  output, e = Popen_Wrapper(Popen('readelf -s \''+path+"\'", shell=True, stdout=PIPE, stderr=PIPE))
  #Check if we have permissions to read Symbol Table
  if('Symbol table' in output):
    #Check for StackCanary support
    if('__stack_chk_fail' in output):
      CurrentProc['StackCanary'] = 'TRUE'
      if(DEBUG > 0):
        print("Stack Canary Found")
    else:
      CurrentProc['StackCanary'] = 'FALSE'
      if(DEBUG > 0):
        print("Stack Canary DNE")
  else:
    CurrentProc['StackCanary']='ScanError'
    if(DEBUG > 0):
      print("Cannot read Program Headers. Please run as root")
  if(DEBUG > 0):
    print('StackCanary: '+CurrentProc['StackCanary'])

def Parse_Procs():
  # COMMAND differs, 1. -bash, 2. [procss]
  Reset_Values()
  #Title order: USER PID CPU MEM VSZ RSS TTY STAT TIME COMMAND
  title = {'USER': 0, 'PID': 1, 'CPU': 2, 'MEM': 3, 'VSZ': 4, 'RSS': 5,
           'TTY': 6, 'STAT': 7, 'START': 8, 'TIME': 9, 'COMMAND': 10}
  ps_raw, e = Popen_Wrapper(Popen('ps -aux', shell=True, stdout=PIPE, stderr=PIPE))
  ps_lines = ps_raw.split('\n')[1:]
  for ps_line in ps_lines:
    ps_line = ps_line.replace('\n', '')
    ps_args = ps_line.split()
    # Skip any not in right format
    if len(ps_args) < len(title):
      continue
    cmd_args = ''
    if len(ps_args) > len(title):
      cmd_args = ' '.join(ps_args[title['COMMAND']+1:])  #Everying after command is arg
    if DEBUG > 3:
      print('PS out:')
      print(ps_args)
      print('Args:')
      print(cmd_args)
    #Break up command and use which if neeeded
    cmd_raw = ps_args[title['COMMAND']]
    cmd_path = ''
    cmd_name = ''
    is_kernel = '[' in cmd_raw
    is_renamed = '(' in cmd_raw
    is_path = '/' in cmd_raw and not is_kernel and not is_renamed
    if len(cmd_raw) > 0 and cmd_raw[-1] == ':':
      cmd_raw = cmd_raw[:-1]
    if len(cmd_raw) > 0 and '-' == cmd_raw[0]:
      cmd_name = cmd_raw[1:]
      cmd_path = cmd_name
    elif is_path:
      #Usually normal path /something/something but not [something/0]
      cmd_split = cmd_raw.split('/')
      cmd_name = cmd_split[-1] if len(cmd_split) > 0 else cmd_raw
      cmd_path = cmd_raw
    elif is_kernel:
      cmd_name = cmd_raw
      #Leave cmd_path blank because it is usually kernal process
      cmd_path = ''
    else:
      cmd_name = cmd_raw
      cmd_path = cmd_raw

    CurrentProc['ProcessName'] = cmd_name
    CurrentProc['ProcessPath'] = cmd_path
    CurrentProc['PID'] = int(ps_args[title['PID']])
    CurrentProc['Protocol'] = 'none'
    CurrentProc['UserName'] = ps_args[title['USER']]
    #Check if can find absolute path
    if not is_path and not is_kernel:
      Proc_Path(ps_args[title['PID']])
      #Change is_path
      is_path = '/' in CurrentProc['ProcessPath'] and not is_kernel and not is_renamed

    #CurrentProc['INODE'] = ino
    CurrentProc['CLIArguments'] = cmd_args
    if CurrentProc['PID'] in procDict.keys():
      if(DEBUG > 0):
        print ('Duplicate Entry')
      #No duplicate for proc
      #Duplicate_Entry(CurrentProc['PID'])
    else:
      #Get process information if not kernal or renamed 
      #Check format is /somethin/something
      Process_Wrapper()
      if is_path:
        Binary_Wrapper()
      #Add proc to dictionary
      Add_Entry(CurrentProc['PID'])
    Reset_Values()

#Ignore `lsof: WARNING: can't stat() fuse.gvfsd-fuse
def Parse_Named_Pipes():
  # TODO change lsof to grep pipe, and add if statement that does readlink

  Reset_Values()
  #TID could be blank
  #Device is %d,%d
  #unnamed pipes link file is at /proc/<pid>/fd/<fd>, readlink can be used on it

  #Title Order: CMD PID TID USER FD TYPE DEVICE SIZE/OFF NODE NAME
  title = {'CMD': 0, 'PID': 1, 'TID': 2, 'USER': 3, 'FD': 4, 'TYPE': 5,
           'DEV': 6, 'SIZE_OFF': 7, 'NODE': 8, 'NAME': 9}
  
  #FIFO are pipes and `grep -v pipe` gets rid of unnamed pipes
  pipe_raw, e = Popen_Wrapper(Popen('lsof -n | grep FIFO | grep -v pipe', shell=True, stdout=PIPE,
                                    stderr=PIPE))
  pipe_lines = pipe_raw.split('\n')
  for pipe_line in pipe_lines:
    pipe_args = pipe_line.split()
    if len(pipe_args) == 0:
      continue
    if DEBUG > 3:
      print('Lsof out:')
      print(pipe_args)

    #Fix missing slots
    try:
      int(pipe_args[title['TID']])
    except ValueError:
      # Put dummy value
      pipe_args.insert(title['TID'], '0')

    #Seperate w/r/u
    state = 'established'
    if 'w' in pipe_args[title['FD']]:
      state = 'listening'

    #Get date last accessed as created is always dash
    date = ''
    try:
      o, e = Popen_Wrapper(
                    Popen('stat --format="%%x" %s' % 
                             pipe_args[title['NAME']], shell=True, stdout=PIPE, stderr=PIPE))
      elapsed = ' '.join(o.split()[:2])
      #Float at end messes up time so get rid of
      date = Convert_Date('.'.join([elapsed.split('.')[0], '0']))
    except:
      date = ''
    if(DEBUG > 0):
      print('|'+str(date)+'|')

    pid = int(pipe_args[title['PID']])
    CurrentProc['ProcessName'] = procDict[pid]['ProcessName']
    CurrentProc['PID'] = pid
    CurrentProc['ProcessPath'] = procDict[pid]['ProcessPath']
    CurrentProc['Protocol'] = 'pipe'
    CurrentProc['LocalAddress'] = pipe_args[title['NAME']]
    CurrentProc['LocalPort'] = pipe_args[title['NODE']]
    CurrentProc['RemoteAddress'] = pipe_args[title['NAME']]
    CurrentProc['RemotePort'] = pipe_args[title['NODE']]
    CurrentProc['State'] = state
    CurrentProc['UserName'] = pipe_args[title['USER']]
    CurrentProc['INODE'] = pipe_args[title['NODE']]
    CurrentProc['ProcessCreatedOn'] = str(date)
    #Add proc to dictionary
    Duplicate_Entry(CurrentProc['PID'])
    Reset_Values()

    

#--------------------------------Wrapper Functions
#parses input from netstat and performs security checks on each process
#Keeping this here for reference of which var is being parsed:
def Parse_Netstat():
  global CurrentProc
  #DEBUG
  if(DEBUG > 0):
    print('Parse_Netstat()------------------------------------------------------------------------')
  #counter
  counter=0
  #holds netstat output
  output = []
  #holds netstat output that includes host and port names
  global netstat_names
  #NOTE: must instert into list to read in special characters for parsing by line e.g. '\n'
  #Get netstat output and append to list
  net_o, net_e = Popen_Wrapper(Popen('netstat -uentap', shell=True, stdout=PIPE, stderr=PIPE))
  net2_o, net2_e = Popen_Wrapper(Popen('netstat -ueWtap', shell=True, stdout=PIPE, stderr=PIPE))
  output.append(net_o)
  netstat_names.append(net2_o)
  #remove duplicate spaces
  output = ' '.join(str(output).split())
  netstat_names = ' '.join(str(netstat_names).split())
  #split netstat output by newline
  output = output.split('\\n')
  netstat_names = netstat_names.split('\\n')
  #remove first two lines of output from netstat; they do not contain data
  del output[0]
  del output[0]
  del netstat_names[0]
  del netstat_names[0]
  #Show all of netstat output
  if(DEBUG > 2):
    print output
    print '----------------------------------------------'
    print netstat_names
  #iterate over entries in output
  for line in output:
    #reset counter
    counter = 0
    #Split elements into list
    varlist=line.split(' ')
    #Check length of varlist to ensure it's valid / not garbage values
    if(len(varlist) < 7):
      #found an invalid or incomplete entry, skip over
      continue
    #Check if we're parsing udp and require a blank 'STATE' entry
    if('udp' in varlist[0]):
      #Insert blank entry to 'STATE' index
      varlist.insert(5,' ')
    #Check for extra entries in list and trim if needed
    if(len(varlist) > 8):
      #Cut off any extra entries
      del varlist[9:]
    #remove Recv-Q Send-Q entries from input
    del varlist[1:3]
    
    if(DEBUG > 1):
      print("varlist: "+ str(varlist))

    #Iterate over each variable in varlist
    # Varlist ex: tcp ip:port ip:port LISTEN User Inode PID/Name
    for var in varlist:
      #DEBUG
      if(DEBUG > 1):
        print ('counter: |'+str(counter)+'|')
        #Show what variable we are parsing for and its intended value
        print ('Var:|'+netstat_var[counter]+'| Val: |'+var+'|')
      
      #Check if we're parsing 'address:port' for local or remote
      #3 because it is incremented to account for port being its own field
      if(counter == 1) or (counter == 3):
        x= var.split(':')
        port = x[len(x)-1]
        #Check Protocol for IPv4, IPv6 connections
        if('6' in CurrentProc[netstat_var[0]]):
          #Get port as last item in list, set to temp item to reduce processing in loop
          #String used to build IPv6 address
          addr = ''
          for y in x:
            #Check if we are at the end of the string
            if(y == port):
              #Remove last colon from address
              addr = addr[0:len(addr)-1]
              if(DEBUG>2):
                  print('addr |'+addr+'|')
              break
            addr += str(y)+':'
          #set IPv6 Address
          CurrentProc[netstat_var[counter]] = addr
          counter+=1
          #set port, check for empty port value
          if(port == '*'):
            CurrentProc[netstat_var[counter]] = ''
          else:
            CurrentProc[netstat_var[counter]] = port
        #Parsing IPv4, no special processing required. 
        else:
          #set IPv4 address
          CurrentProc[netstat_var[counter]] = x[0]
          counter+=1
          #set port
          #Check if empty :::port
          if(port == '*'):
            CurrentProc[netstat_var[counter]] = ''
          else:
            CurrentProc[netstat_var[counter]] = x[1]
        if(DEBUG > 0):
          print('Address: |'+CurrentProc[netstat_var[counter-1]]+'| Port: |'+CurrentProc[netstat_var[counter]]+'|')
      #Check if we're parsing State
      elif(counter == 5):
        #Check if current line from netstat is UDP (since it has no state)
        if('udp' in CurrentProc['Protocol']):
            CurrentProc[netstat_var[counter]] = ''
        else:
            if(var == 'LISTEN'):
              CurrentProc[netstat_var[counter]] = 'listening'
            elif(var == 'ESTABLISHED'):
              CurrentProc[netstat_var[counter]] = 'established'
            elif('TIME_WAIT' in var):
              CurrentProc[netstat_var[counter]] = 'time wait'
            elif('FIN_WAIT' in var):
              CurrentProc[netstat_var[counter]] = 'fin wait'
            else:
              CurrentProc[netstat_var[counter]] = var
      #Check if we're parsing 'PID/ProcessName'
      elif(counter == 8):
        #Check if there's a valid PID/ProcessName
        if(var == '-'):
          if DEBUG > 3:
            print('Fixing dash PID')
          x = ['0','-']
        else:
          x=var.split('/')
        #set PID
        CurrentProc[netstat_var[counter]] = int(x[0])
        #Increment counter
        counter+=1
        #Set host and port names for local and remote:
        Host_Port_Name(CurrentProc['INODE'])
        
        if(DEBUG > 0):
          print('PID: |'+str(CurrentProc[netstat_var[counter-1]])+'| ProcessName: |'+CurrentProc[netstat_var[counter]]+'|')
        #Check if PID is already in the dictionary, indicating it's a duplicate
        if CurrentProc['PID'] in procDict.keys():
          if(DEBUG > 0):
            print ('Duplicate Entry')
          #Copy over values
          Duplicate_Entry(CurrentProc['PID'])
        else:
          #Get process information
          #Set ProcessPath
          Proc_Path(CurrentProc['PID'])
          #Set ProcessName
          Proc_Name()
          Process_Wrapper()
          #Get Binary information, evaluate ASLR
          Binary_Wrapper()
          #Add proc to dictionary
          Add_Entry(CurrentProc['PID'])
        #Reset values
        Reset_Values()
        break
      else:
        #Use the netstat value as a key for CurrentProc and set value to var
        CurrentProc[netstat_var[counter]] = var
      #increment counter
      counter+=1
      if(DEBUG>1):
        print(CurrentProc)
	#NOTE/TODO:To get port name, use: socket.getservbyport(sock#)

def Parse_Domain_Sockets():
  global CurrentProc
  Reset_Values()
  #DEBUG
  if(DEBUG > 0):
    print('Parse_Domain_Sockets()------------------------------------------------------------------------')
  #counter
  counter=0
  #holds netstat output
  output = []
  #NOTE: must instert into list to read in special characters for parsing by line e.g. '\n'
  #Get netstat output and append to list
  o, e = Popen_Wrapper(Popen('netstat -xp', shell=True, stdout=PIPE, stderr=PIPE))
  output.append(o)
  #remove duplicate spaces
  output = ' '.join(str(output).split())
  #split netstat output by newline
  output = output.split('\\n')
  #remove first two lines of output from netstat; they do not contain data
  del output[0]
  del output[0]
  #Show all of netstat output
  if(DEBUG > 2):
    print('Output:')
    print output
  #iterate over entries in output
  for line in output:
    #reset counter
    counter = 0
    #Split elements into list
    varlist=line.split(' ')
    
    #Find position to slice to in list for entry removal
    p = 0
    for y in varlist:
        if(y ==']'):
          #remove RefCnt and Flag entries from input
          del varlist[0:p+1]
          break
        #increment coutner
        p += 1 

    #Get rid of extra at end if there is one
    if varlist[len(varlist)-1] == '':
      varlist = varlist[:len(varlist)-1]

    #Check if Type is DGRM; it doesn't have a socket state
    if('DGRAM' in varlist[0]):
        varlist.insert(1,'')
    #Check for blank path entries
    if(len(varlist)==4):
        varlist.insert(4,'');
    
    if(DEBUG > 1):
      print("varlist: "+ str(varlist))
    
    #Check length of varlist to ensure it's valid / not garbage values
    if((len(varlist) < 5) or (len(varlist) > 5)):
        if(DEBUG>2):
            print("Skipping entry: "+ str(varlist))
      #skip running checks for entry
        continue
    
    #Iterate over each variable in varlist
    for var in varlist:
      #DEBUG
      if(DEBUG > 1):
        print ('counter: |'+str(counter)+'|')
        #Show what variable we are parsing for and its intended value
        print ('Var:|'+domain_var[counter]+'| Val: |'+var+'|')
      
      if(counter==0):
        CurrentProc['Protocol'] = var
      #Check if we're parsing 'PID/ProcessName'
      elif(counter==3):
        #Check if there's a valid PID/ProcessName
        if(var == ''):
          x = ['0','-']
        else:
          x=var.split('/')
        #set PID
        CurrentProc['PID'] = int(x[0])
        CurrentProc['ProcessName'] = x[1]
        if(DEBUG > 0):
          print('PID: |'+str(CurrentProc[domain_var[counter-1]])+'| ProcessName: |'+CurrentProc['ProcessName']+'|')
        
      #Check if we're parsing path
      elif(counter==4):
        #TODO: Remove duplicate entries with the exception of PID 1
        #Check if PID is already in the dictionary, indicating it's a duplicate
        if CurrentProc['PID'] in procDict.keys():
          if(DEBUG > 0):
            print ('Duplicate Entry')
          #Copy over values
          Duplicate_Entry(CurrentProc['PID'])
        else:
          #Get process information
          Domain_Process_Wrapper()
          #Add proc to dictionary
          Add_Entry(CurrentProc['PID'])
        #Add proc to dictionary
        #Add_Entry(CurrentProc['PID'])
        #Reset values for globals
        Reset_Values()
      else:
        #Use the netstat value as a key for CurrentProc and set value to var
        CurrentProc[domain_var[counter]] = var
      #increment counter
      counter+=1
      if(DEBUG>1):
        print(CurrentProc)

#Process wrapper for parse_netstat()
def Process_Wrapper():
  pid = int(CurrentProc['PID'])
  if(DEBUG > 0):
    print("Process_Wrapper() |"+str(pid)+'|')
  #Set architecture for process
  Architecture(pid)
  #Calculate and set date process was created, sets ProccessCreatedOn
  Proc_Created_On(pid)
  #Get the username associated with the current running process, sets UserName
  Proc_User_Name(pid)
  #Determine if the process supports PIE, sets PIE_process
  PIE_Process(pid)
  #Check for system ASLR support, sets SysASLR
  ASLR(pid)
  #Set RELRO, Stack Canary, and DEP
  Proc_Check(CurrentProc['ProcessPath'])

#Binary wrapper for parse_netstat()
#preconditions: PID and ProcessPath are set in CurrentProc
def Binary_Wrapper():
  File_Info()
  PIE_Binary(CurrentProc['ProcessPath'])
  #Evaluate ASLR
  if ((SysASLR == 'TRUE') and (PIE_binary == 'TRUE') and (PIE_process == 'TRUE')):
    CurrentProc['ASLR'] = 'TRUE'
  else:
    CurrentProc['ASLR'] = 'FALSE'

#Process wrapper for Parse_Netstat()
def Domain_Process_Wrapper():
  pid = int(CurrentProc['PID'])
  if(DEBUG > 0):
    print("Domain_Process_Wrapper() |"+str(pid)+'|')
  #Set architecture for process
  Architecture(pid)
  #Calculate and set date process was created, sets ProccessCreatedOn
  Proc_Created_On(pid)
  #Get the username associated with the current running process, sets UserName
  Proc_User_Name(pid)
  #Determine if the process supports PIE, sets PIE_process
  PIE_Process(pid)
  #Check for system ASLR support, sets SysASLR
  ASLR(pid)
  #Set RELRO, Stack Canary, and DEP

#Binary wrapper for Parse_Netstat()
#preconditions: PID and ProcessPath are set in CurrentProc
def Domain_Binary_Wrapper():
  File_Info()
  PIE_Binary(CurrentProc['ProcessPath'])
  #Evaluate ASLR
  if ((SysASLR == 'TRUE') and (PIE_binary == 'TRUE') and (PIE_process == 'TRUE')):
    CurrentProc['ASLR'] = 'TRUE'
  else:
    CurrentProc['ASLR'] = 'FALSE'

#Check if all dependencies are met such as netstat
def Dep_Check():
  #Don't use wrapper as os.popen not needed
  _, net_e = Popen('which netstat', shell=True, stdout=PIPE, stderr=PIPE).communicate()
  if len(net_e) != 0:
    sys.exit('ERROR: Please install netstat and run again')
  _, lsof_e = Popen('which lsof', shell=True, stdout=PIPE, stderr=PIPE).communicate()
  if len(lsof_e) != 0:
    sys.exit('ERROR: Please install lsof and run again')

#--------------------------------Main Function
#gathers all of the required information and outputs to a file
def AHA_Main():
  global DEBUG
  if os.getuid() != 0:
    sys.exit('ERROR: Please run as root or use sudo')
  Dep_Check()
  debugRecallFile = ''
  #Check if there was a variable passed into the system and that it's an integer
  try:
    if(len(sys.argv) > 1):
      if(sys.argv[1] == 'help') or (sys.argv[1] == '-h'):
        print('\nTo have the script show intermediary output, include an input parameter 1-3 \nDebugging: 1, Verbose: 2, Developer: 3')
        print('1: \'Debugging\' shows what function is being called and basic parameters used')
        print('2: \'Verbose\' shows intermediary results, other parameters, and some control logic')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
        print('3: \'Developer\' shows extra outputs to help check if variables are parsed and set correctly')
        print('***Please note that performace degrades with each level of debugging***\n')
        return
      elif((int(sys.argv[1]) < 0) or (int(sys.argv[1]) > 5)):
        print("Please enter a valid parameter for the DEBUG variable: Debugging: 1, Verbose: 2, Developer: 3, Dev out: 4, Dev in: 5")
        return
      else:
        print('Setting DEBUG to: '+sys.argv[1])
        if int(sys.argv[1]) == 4 or int(sys.argv[1]) == 5:
          if len(sys.argv) < 3:
            print('Dev out requires a filename')
            return
          print('Debug file is %s' % sys.argv[2])
          debugRecallFile = sys.argv[2]
        DEBUG = int(sys.argv[1])
  except ValueError:
    print('Parameter error, try -h, help or a value between 1 and 5')
    return
  #Get popen recall if DEBUG=5
  Read_Debug_Recall(debugRecallFile)
  print('AHA-Linux-Scraper: Scanning System...')
  #Set current scan time, detection time
  Detection_Time()
  #Set the column header formating for the CSV file
  columnHeaders = "\"ProcessName\",\"PID\",\"ProcessPath\",\"Protocol\",\"LocalAddress\",\"LocalPort\",\"LocalHostName\",\"LocalPortName\",\"RemoteAddress\",\"RemotePort\",\"RemoteHostName\",\"RemotePortName\",\"State\",\"ProductName\",\"FileDescription\",\"FileVersion\",\"Company\",\"ProcessCreatedOn\",\"UserName\",\"ProcessServices\",\"ProcessAttributes\",\"DetectionTime\",\"ARCH\",\"ASLR\",\"PIE-Binary\",\"DEP\",\"RELRO\",\"StackCanary\",\"CLIArguments\""
  #Clear out BinaryAnalysis.csv, no wrapper as this is not a used value
  Popen("echo \'"+columnHeaders+"\' > BinaryAnalysis.csv", shell=True)
  CurrentProc = { 'ProcessName' : '', 'PID' : 0, 'ProcessPath' : '', 'Protocol' : '', 'LocalAddress' : '', 'LocalPort' : '', 'LocalHostName' : '', 'LocalPortName' : '', 'RemoteAddress' : '', 'RemotePort' : '', 'RemoteHostName' : '', 'RemotePortName' : '', 'State' : '', 'ProductName' : '', 'FileDescription' : '', 'FileVersion' : '', 'Company' : '', 'ProcessCreatedOn' : '', 'UserName' : '', 'ProcessServices' : '', 'ProcessAttributes' : '', 'DetectionTime' : '', 'ARCH' : '', 'ASLR' : '', 'PIE-Binary' : '', 'DEP' : '', 'RELRO' : '', 'StackCanary' : '', 'INODE' : ''}
  #place PID 0, initial duplicate entry, in procDict
  Init_Dict()
  print('Scanning Active Network Connections...')
  Parse_Netstat()
  Parse_Procs()
  Parse_Named_Pipes()
  #print('Scanning Domain Sockets...')
  #Parse_Domain_Sockets()
  #Write info to CSV
  Write_To_File()
  Write_If_Debug(debugRecallFile)
  print('\n\tScan Complete.')
  print('\tSee \'BinaryAnalysis.csv\' for output.')


AHA_Main()
