# AHA-Scraper-Linux
This repository contains the Linux host Scraper portion of the AHA (AttackSurface Host Analyzer) project which provides scan data which can then be visualized using the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Developed by ESIC, Washington State University.

# User Instructions
[Click here for user walkthrough / documentation](https://aha-project.github.io/)

# Warning / Bugs
As of August 1st 2018, we have marked this scraper stable. It still has not received a lot of external testing as of yet, but has been tested internally on CentOS 7.5 (a RHEL derivative), Kali 2018.2 (a Debian derivative), and at present we have no known issues.

There is no implied waranty, or liability assumed by us if you run this, but there should not be anything that can cause side effects either.

# Scraper usage
Clone or download the repo from github

To run the scraper:
1. Open a shell
1. `cd` to the directory containing the script
1. Run the script by typing `sudo python python_aha.py`
1. Install any packages that the script says are missing.
1. Display the help menu with `sudo python python_aha.py -h`
1. When run, it will first scan then the data is processed. No new data will be collected in the processing phase. 

## Scraper Help Menu
To use a command line argument follow the base command(`sudo python python_aha.py`) 
with any number of the below arguments. Arguments must appear in a space separated 
list. Any arguments requiring additional fields must have them supplied immediately 
after the argument. Consult the `Defaults` and `Normal Behavior` sections to 
understand how the program works without additional arguments. All argument fields are 
optional, just supply an underscore instead of the field.  
- `h` : Display the help menu.  
- `H` : Do not compute executable hashes.  
- `k` : Ignore kernel processes.  
- `e` : Ignore network entries.  
- `n` : Ignore named pipes.  
- `p` : Ignore all processes.  
  - This will limit the named pipe info. A large amount of infor may be missing.  
- `r` : For repeated scan use most recent scan time. Default is first time it was found.  
- `l` {seconds} : Long scan. Time to scan in seconds.  
- `f` {file}    : Output file to write results to. Relative shell's working directory.  
- `d` {level}   : (**DEV**)Debug menu. Requires 1 arguments, debug level {int}.  
- `o` {file}    : (**DEV**)Output recall file. Requires 1 argument, filename.  
- `i` {file}    : (**DEV**)Simulate run from outputted recall. Requires 1 argument, filename.  

### Examples 
- `sudo python python_aha.py -l 320 -k`: To scan for 320 seconds and not output kernel processes.  
- `sudo python python_aha.py -p`: To scan without processes. Very limited without 
the process information.  
- `sudo python python_aha.py -f _`: Uses the default file `BinaryAnalysis.csv`.  
- `sudo python python_aha.py -f "s p a c e.csv"`: Outputs to a space seperated file.  

## Defaults (With underscore instead of field)  
- `f` outputs to `BinaryAnalysis.csv`  
- `o`/`i` outputs to `debug-out.json`.  
- `l` runs for 2 minutes or `120` seconds.  
- `d` runs as debug level 4.  
- `r` shows first scan it was found in.  


## Normal Behavior 
- There are three scans:
  - Process 
  - Network
  - Named Pipe
- Scans without the `l` argument will run one cycle which is faster than one second.
Although, scans on the edge of a second may show scanned items in different times.  
- Scan over time defaults to detection time being the first time that row was scanned. 

The resulting `BinaryAnalysis.csv` can either be viewed in a text/spreadsheets app (such as Excel) or visualized in the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Note: The program must be run as sudo.
