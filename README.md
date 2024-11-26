PowerShellTracer

PowerShellTracer is a security monitoring tool designed to detect suspicious PowerShell activity on Windows systems by scanning event logs for Indicators of Compromise (IOCs). It focuses on detecting malicious 

PowerShell commands, which are often used in attack scenarios like malware execution, exploitation, and system compromise.

Features

IOC Detection: Identifies suspicious PowerShell commands (e.g., Invoke-WebRequest, Base64, IEX, etc.) that may indicate an attack.

Real-Time Monitoring: Monitors Windows event logs in real time and triggers alerts when critical IOCs are detected.

Telegram Alerts: Sends instant alerts to a Telegram chat whenever an IOC is found, helping security teams stay informed.

Event Log Parsing: Retrieves and analyzes PowerShell-related event logs from multiple log sources, such as Microsoft-Windows-PowerShell/Operational, Security, and System.

CSV Export: Saves detected events to a CSV file for further analysis and record-keeping.


Customizable Detection: Users can customize which IOCs to search for by modifying the regular expressions and event IDs.


Installation

Clone the repository:

git clone https://github.com/<your-username>/PowerShellTracer.git

Install the required dependencies:

pip install -r requirements.txt

Ensure that you have the correct permissions to read event logs on your Windows machine. Run the script as an administrator if necessary.

Configuration

Before running the tool, update the following parameters:

API Token: Get your Telegram bot API token by creating a bot via BotFather.

Chat ID: Obtain your Telegram chat ID by sending a message to your bot and using the /getUpdates endpoint.
Usage

You can run the tool in one of two modes:

Fetch Events: Fetch event logs from the past 6 hours, detect IOCs, and save the results to a CSV file.

python PowerShellTracer.py

Live Tracking Mode: Continuously monitor the event logs and display new events as they are detected in real time.

python PowerShellTracer.py

Mode Selection:

Choose mode 1 for fetching events and saving them to a CSV file.

Choose mode 2 for live tracking and monitoring event logs in real time.

Example Output

When suspicious activity is detected, an alert message like the following will be sent to your Telegram chat:


There is An IOC Found
Contributing


![image](https://github.com/user-attachments/assets/86d9aaed-2361-446a-a70e-f3bcc34f08d7)

![image](https://github.com/user-attachments/assets/64fa6be0-ed99-40e7-b0cf-fce7a3f0dbc3)

![image](https://github.com/user-attachments/assets/1d01cb2a-e0ee-4765-9303-3531c5a26462)





If you'd like to contribute to this project, feel free to fork the repository, create a branch, and submit a pull request with your changes.



