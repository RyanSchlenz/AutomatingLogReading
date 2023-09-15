# AutomatingLogReading
Using Python to automate reading logs to detect specific patterns

Explaining what the code does: 

Import Statements: The script starts by importing necessary Python modules:

re: The re module is used for working with regular expressions.
Evtx.Evtx as evtx: It imports the Evtx module and aliases it as evtx. This module is used for parsing Windows Event Log (EVTX) files.
datetime from datetime: This module is used for working with dates and times.
openLogFile Function: This function is used for opening a generic log file specified by the path. It reads the file line by line and yields each log entry.

openEvtxFile Function: This function is used for opening an EVT (Windows Event Log) file specified by the path. It uses the evtx module to read and yield log entries from the EVT file.

Log Parsing Functions:

parseZeekConn: This function is designed to parse log entries in a format related to Zeek connection logs.
parseZeekdns: This function is designed to parse log entries related to Zeek DNS logs.
parseZeekHttp: This function is designed to parse log entries related to Zeek HTTP logs.
parseSmb: This function is designed to parse log entries related to SMB (Server Message Block) protocol logs.
These functions split the log entries into fields and create dictionaries with meaningful field names.

parseEvtx Function: This function is used to parse Windows Event Log (EVTX) entries. It extracts timestamp, event ID, and event data from an EVT XML record and stores them in a dictionary.

detectRundll32 Function: This function opens an EVT file specified by the path for Windows Event Log data. It then iterates through the log entries, to parse each entry using the parseEvtx function. If the event ID is "4688" and the command line contains "rundll32" while the parent process name contains "powershell" or "cmd," it prints the command line. 
