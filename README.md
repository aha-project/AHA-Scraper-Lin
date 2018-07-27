# AHA-Scraper-Linux
This repository contains the Linux host Scraper portion of the AHA (AttackSurface Host Analyzer) project which provides scan data which can then be visualized using the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Developed by ESIC, Washington State University.

# User Instructions
[Click here for user walkthrough / documentation](https://aha-project.github.io/)

# Warning / Bugs
Initial Linux support is debuting in late July 2018. For the next several weeks, there are some known bugs we are working on fixing, and probably some that are left to find. There is no implied waranty, or liability assumed by us if you run this, but so far on RHEL7/CentOS7/Kali2018.2/Ubuntu18.04 everything seems to mostly work. BinaryAnalysis.csv files may require light tweaking to get to render properly in the AHA-GUI (usually because a field is missing/invalid). We're working on it, this warning will be removed at such time that our known bugs list is smaller :)

# Scraper usage
Clone or download the repo from github

To run the scraper:
1. Open a shell
1. `cd` to the directory containing the script
1. Run the script by typing `./AHA-Scraper-Linux.sh`

The resulting `BinaryAnalysis.csv` can either be viewed in a text/spreadsheets app (such as Excel) or visualized in the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Note: If the script is not executable you can fix that by running `chmod +x ./AHA-Scraper-Linux.sh`
