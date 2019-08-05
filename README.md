# AHA-Scraper-Linux
This repository contains the Linux host Scraper portion of the AHA (AttackSurface Host Analyzer) project which provides scan data which can then be visualized using the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Developed by ESIC, Washington State University.

# User Instructions
[Click here for user walkthrough / documentation](https://aha-project.github.io/)

# Warning / Bugs
As of August 5st 2019, we released the introductory version of the v0.6.0 beta. It still has not received a lot of external testing as of yet, but has been tested internally on CentOS 7.6 (a RHEL derivative), Kali 2019.2 (a Debian derivative), and at present we have only minor known issues, which are presently ignored in the current version of AHA-GUI (v0.6.8b113+).

There is no implied waranty, or liability assumed by us if you run this, but there should not be anything that can cause side effects either.

# Scraper usage
Clone or download the repo from github

To run the scraper:
1. Open a shell
1. `cd` to the directory containing the script
1. Run the script by typing `python python_aha.py`

The resulting `BinaryAnalysis.csv` can either be viewed in a text/spreadsheets app (such as Excel) or visualized in the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

