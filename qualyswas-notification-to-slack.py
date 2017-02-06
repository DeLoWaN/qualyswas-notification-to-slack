#!/usr/bin/env python3

import re
import sys

status = re.compile(r"Scan Status :([A-Z\s]+[a-z\s]+):([A-Z\s]+[a-z\s]+)Authentication Status:([A-Z\s]+[a-z\s]+)")
vulnerabilities = re.compile(r"Summary of Crawling(?: \(\+\/\-\)|)\n\nLinks Crawled : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\n\n\nSummary of Vulnerabilities(?: \(\+\/\-\)|)\n\nSeverity 5 \"Urgent\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 4 \"Critical\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 3 \"Serious\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 2 \"Medium\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 1 \"Minimal\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)")

text = '''Launch Type : Scheduled

Scan Status : Finished: Scan stopped after encountering too many errors on
server side
Authentication Status: Successful

Next Action : N/A


------------------------------------------------------------
------------------------------------------------------------
------------------

Scan Statistics
================================================

Summary of Crawling

Links Crawled : 303


Summary of Vulnerabilities

Severity 5 "Urgent" : 0 (=)
Severity 4 "Critical" : 0
Severity 3 "Serious" : 0 (+1)
Severity 2 "Medium" : 0 (-4)
Severity 1 "Minimal" : 2

Total : 2


Summary of Sensitive Contents

Severity 5 "Urgent" : 0
Severity 4 "Critical" : 0
Severity 3 "Serious" : 0
Severity 2 "Medium" : 0
Severity 1 "Minimal" : 0

Total : 0


Summary of Information Gathered

Severity 5 "Urgent" : 0
Severity 4 "Critical" : 0
Severity 3 "Serious" : 1
Severity 2 "Medium" : 2
Severity 1 "Minimal" : 16

Total : 19
'''

text = ''.join(sys.stdin.readlines())

obj = status.search(text)

scanstatus = obj.group(1).replace('\n',' ').strip()
scanstatusdetail = obj.group(2).replace('\n',' ').strip()
authenticationstatus = obj.group(3).replace('\n',' ').strip()

obj = vulnerabilities.search(text)

linkscrawled = obj.group(1)

urgent = obj.group(2)
critical = obj.group(3)
serious = obj.group(4)
medium = obj.group(5)
minimal = obj.group(6)

print('Scan Status : {} - {}\nAuthentication Status: {}\n\nLinks Crawled: {}\n\nSummary of Vulnerabilities :\n\nSeverity 5 "Urgent" : {}\nSeverity 4 "Critical" : {}\nSeverity 3 "Serious" : {}\nSeverity 2 "Medium" : {}\nSeverity 1 "Minimal" : {}'.format(
	scanstatus,
	scanstatusdetail,
	authenticationstatus,
	linkscrawled,
	urgent,
	critical,
	serious,
	medium,
	minimal
	))
