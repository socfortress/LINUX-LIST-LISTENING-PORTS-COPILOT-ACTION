## List Listening Ports

This script enumerates all listening TCP and UDP ports on the system, providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `List Listening Ports` script uses `lsof` to identify all processes with open listening ports, collecting protocol, port, PID, program name, and executable path. Output is formatted as JSON for active response workflows.

### Script Details

#### Core Features

1. **Port Enumeration**: Lists all listening TCP and UDP ports.
2. **Process Metadata**: Collects protocol, port, PID, program name, and executable path.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./ListListeningPorts
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/ListListeningPorts-script.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file
- Rotates the detailed log file if it exceeds the size limit
- Logs the start of the script execution

#### 2. Port Collection
- Uses `lsof` to enumerate all listening TCP and UDP ports
- Collects process metadata for each port

#### 3. JSON Output Generation
- Formats port details into a JSON array
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "list_listening_ports",
  "ports": [
    {
      "protocol": "tcp",
      "port": "22",
      "pid": "1234",
      "program": "sshd",
      "program_path": "/usr/sbin/sshd"
    },
    {
      "protocol": "udp",
      "port": "53",
      "pid": "5678",
      "program": "named",
      "program_path": "/usr/sbin/named"
    }
  ],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access process and port information
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure read access to `/proc` and execution of `lsof`
2. **Missing Data**: Some ports may not be detected if `lsof` is missing or restricted
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./ListListeningPorts
```

### Contributing

When modifying this script:
1. Maintain the port enumeration and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
