#!/usr/bin/env python3

import re
import sys
import slackweb
import argparse

# Parse arguments
parser = argparse.ArgumentParser(description='Forwards Qualys WAS notification emails to Slack channel with severity control')
parser.add_argument('-U', '--slack-url', required=True, help='URL of Slack Incoming Webhook')
parser.add_argument('-S', '--severity', help='Severity on which the alert should be sent', choices=['urgent','critical','serious','medium','minimal'], default='critical')
args = parser.parse_args()

#slack = slackweb.Slack(url="https://hooks.slack.com/services/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")
slack = slackweb.Slack(url=args.slack_url)

# Prepare regexes
status = re.compile(r"Scan Status :([A-Z\s]+[a-z\s]+):([A-Z\s]+[a-z\s]+)Authentication Status:([A-Z\s]+[a-z\s]+)")
vulnerabilities = re.compile(r"Summary of Crawling(?: \(\+\/\-\)|)\s+Links Crawled : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\s+\nSummary of Vulnerabilities(?: \(\+\/\-\)|)\s+Severity 5 \"Urgent\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 4 \"Critical\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 3 \"Serious\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 2 \"Medium\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)\nSeverity 1 \"Minimal\" : (\d+)(?: \((?:=|\+\d+|\-\d+)\)|)")

# Defines severity
if args.severity == 'urgent':
	severity = 5
if args.severity == 'critical':
	severity = 4
if args.severity == 'serious':
	severity = 3
if args.severity == 'medium':
	severity = 2
if args.severity == 'minimal':
	severity = 1

# Read email from stdin
text = ''.join(sys.stdin.readlines())

# Grep statuses
obj = status.search(text)
scanstatus = obj.group(1).replace('\n',' ').strip()
scanstatusdetail = obj.group(2).replace('\n',' ').strip()
authenticationstatus = obj.group(3).replace('\n',' ').strip()

# Grep vulnerabilities
obj = vulnerabilities.search(text)
linkscrawled = obj.group(1)
urgent = obj.group(2)
critical = obj.group(3)
serious = obj.group(4)
medium = obj.group(5)
minimal = obj.group(6)

# Notify
sendNotification = False
if  (scanstatus != 'Finished' or (scanstatus == 'Finished' and scanstatusdetail != 'OK')) or \
	(authenticationstatus != 'Successful') or \
	(int(urgent) > 0 and severity <= 5) or \
	(int(critical) > 0 and severity <= 4) or \
	(int(serious) > 0 and severity <= 3) or \
	(int(medium) > 0 and severity <= 2) or \
	(int(minimal) > 0 and severity <= 1):
	sendNotification = True
	print('NOTIF')



#slack.notify(text='Scan Status : {} - {}\nAuthentication Status: {}\n\nLinks Crawled: {}\n\nSummary of Vulnerabilities :\n\nSeverity 5 "Urgent" : {}\nSeverity 4 "Critical" : {}\nSeverity 3 "Serious" : {}\nSeverity 2 "Medium" : {}\nSeverity 1 "Minimal" : {}'.format(
#	scanstatus,
	#scanstatusdetail,
	#authenticationstatus,
	#linkscrawled,
	#urgent,
	#critical,
	#serious,
	#medium,
	#minimal
	#))
