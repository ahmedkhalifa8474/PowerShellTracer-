import win32evtlog
import csv
from datetime import datetime, timedelta

def fetch_powershell_events(hours=6):
    # Define the log and event source
    log_type = "Microsoft-Windows-PowerShell/Operational"
    
    # Expanded list of PowerShell-related Event IDs
    event_ids_to_search = {
        4103, 4104, 4105, 4106, 800, 600, 4107, 4108, 8000, 4000
    }

    # Expanded list of security-related Event IDs
    security_event_ids = {
        4688, 4689, 4648, 4672, 4768, 4624, 4625, 4673
    }

    # Sysmon Event IDs for system monitoring
    sysmon_event_ids = {1, 3, 10, 11, 13}

    # Combine all event IDs
    event_ids_to_search.update(security_event_ids)
    event_ids_to_search.update(sysmon_event_ids)

    time_threshold = datetime.now() - timedelta(hours=hours)

    try:
        # Open the event log
        log_handle = win32evtlog.OpenEventLog(None, log_type)

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []

        while True:
            # Read events in chunks
            records = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if not records:
                break

            for record in records:
                # Filter by Event IDs and time threshold
                if record.EventID in event_ids_to_search and record.TimeGenerated >= time_threshold:
                    # Extract user info (if available)
                    user_info = "No User Data"
                    if hasattr(record, "StringInserts") and record.StringInserts:
                        # Check for user info in StringInserts if available
                        user_info = record.StringInserts[1] if len(record.StringInserts) > 1 else "No User Info"
                    
                    # Safely extract command data
                    command = record.StringInserts[-1] if hasattr(record, "StringInserts") and record.StringInserts else "No Data Available"
                    
                    process_id = "Unknown"
                    if hasattr(record, "EventCategory"):
                        process_id = str(record.EventCategory)  # Use EventCategory as a fallback
                    
                    event_data = {
                        "EventID": record.EventID,
                        "Timestamp": record.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "Command": command,
                        "User": user_info,
                        "ProcessID": process_id,
                    }
                    events.append(event_data)
        win32evtlog.CloseEventLog(log_handle)

        return events

    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def save_to_csv(events, filename="PowerShell.csv"):
    try:
        # Check if file exists and if not, create it with headers
        file_exists = False
        try:
            with open(filename, "r"):
                file_exists = True
        except FileNotFoundError:
            pass

        # Open the file in append mode, creating if it doesn't exist
        with open(filename, "a", newline="") as csvfile:
            fieldnames = ["EventID", "Timestamp", "Command", "User", "ProcessID"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header if the file is new
            if not file_exists:
                writer.writeheader()

            # Write event data
            for event in events:
                writer.writerow(event)

        print(f"Events have been written to {filename}")
    except Exception as e:
        print(f"Failed to write to file: {e}")

if __name__ == "__main__":
    events = fetch_powershell_events(6)  # Last 6 hours
    if events:
        print(f"Found {len(events)} PowerShell events in the last 6 hours:")
        # Save the events to PowerShell.csv
        save_to_csv(events)
    else:
        print("No PowerShell events found in the last 6 hours.")
