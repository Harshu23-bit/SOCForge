from app.incident import IncidentStore
from app.ingestion import normalize_wazuh_alert
from app.schemas import IncidentStatus


def test_incident_creation_and_retrieval():
    store = IncidentStore()

    alert = {
        "rule": {
            "id": "100001",
            "level": 10,
            "description": "Test security event",
        },
        "agent": {
            "id": "001",
            "name": "TEST-HOST",
        },
    }

    detection = normalize_wazuh_alert(alert)
    incident = store.create(detection)

    assert incident.incident_id.startswith("INC-")
    assert incident.status == IncidentStatus.NEW

    retrieved = store.get(incident.incident_id)

    assert retrieved is not None
    assert retrieved.incident_id == incident.incident_id
    assert retrieved.detection.rule_id == "100001"
    assert retrieved.detection.agent.name == "TEST-HOST"


def test_incident_status_update():
    store = IncidentStore()

    alert = {
        "rule": {
            "id": "100002",
            "level": 12,
            "description": "Another test event",
        }
    }

    detection = normalize_wazuh_alert(alert)
    incident = store.create(detection)

    updated = store.update_status(
        incident.incident_id,
        IncidentStatus.TRIAGED,
    )

    assert updated is not None
    assert updated.status == IncidentStatus.TRIAGED

    retrieved = store.get(incident.incident_id)

    assert retrieved is not None
    assert retrieved.status == IncidentStatus.TRIAGED
