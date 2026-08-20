from app.ingestion import normalize_wazuh_alert
from app.schemas import Severity


def test_normalize_wazuh_alert():
    alert = {
        "timestamp": "2026-08-17T02:15:30+05:30",
        "rule": {
            "id": "100201",
            "level": 12,
            "description": "Suspicious process execution detected",
        },
        "agent": {
            "id": "001",
            "name": "SOC-WIN01",
            "ip": "192.168.1.25",
            "os": {
                "name": "Microsoft Windows 11",
            },
        },
        "process": {
            "pid": 6840,
            "ppid": 1200,
            "name": "powershell.exe",
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": (
                "powershell.exe -ExecutionPolicy Bypass "
                "-EncodedCommand TEST"
            ),
            "user": r"CORP\analyst",
        },
        "data": {
            "srcip": "192.168.1.25",
            "dstip": "8.8.8.8",
            "dstport": "443",
        },
    }

    event = normalize_wazuh_alert(alert)

    assert event.source.value == "wazuh"
    assert event.rule_id == "100201"
    assert event.rule_level == 12
    assert event.severity == Severity.HIGH

    assert event.agent.id == "001"
    assert event.agent.name == "SOC-WIN01"
    assert event.agent.ip == "192.168.1.25"

    assert event.process.pid == 6840
    assert event.process.ppid == 1200
    assert event.process.name == "powershell.exe"
    assert event.process.user == r"CORP\analyst"

    assert event.src_ip == "192.168.1.25"
    assert event.dst_ip == "8.8.8.8"
    assert event.dst_port == 443


def test_missing_telemetry_is_not_fabricated():
    alert = {
        "rule": {
            "id": "999999",
            "level": 5,
            "description": "Test event",
        }
    }

    event = normalize_wazuh_alert(alert)

    assert event.rule_id == "999999"
    assert event.rule_level == 5

    assert event.agent.id is None
    assert event.agent.name is None
    assert event.agent.ip is None

    assert event.process.pid is None
    assert event.process.ppid is None
    assert event.process.name is None

    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.file_path is None
    assert event.file_hash is None
