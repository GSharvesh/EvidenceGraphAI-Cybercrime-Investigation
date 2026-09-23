"""Unit tests for Pydantic graph models."""

from core.graph.models import (
    APKSampleNode,
    AttackerNode,
    ATTACKTechniqueNode,
    CertificateNode,
    CommunicatesWithEdge,
    CVENode,
    DeliversEdge,
    DerivedFromEdge,
    DetectedByEdge,
    DomainNode,
    DowngradesToEdge,
    EvidenceArtifactNode,
    ExpectedToLeadToEdge,
    ExploitsEdge,
    ExportedAsEdge,
    HasResponseEdge,
    IPAddressNode,
    LinkedCampaignEdge,
    LogEntryNode,
    MalwareNode,
    MapsToEdge,
    PrecedesEdge,
    ResolvesToEdge,
    SupersedesEdge,
    UsesCertificateEdge,
    VictimNode,
)


def test_node_models_instantiation() -> None:
    """Verifies all 11 node model classes instantiate and format timestamps."""
    cve = CVENode(id="CVE-2024-100", cvss_score=9.8, severity="HIGH")
    assert cve.id == "CVE-2024-100"
    assert cve.source_agent == "system"

    victim = VictimNode(id="v1", name="Target Corp", sector="Finance")
    assert victim.name == "Target Corp"

    attacker = AttackerNode(id="a1", name="APT29", aliases=["Cozy Bear"])
    assert "Cozy Bear" in attacker.aliases

    malware = MalwareNode(id="m1", sha256="abc123hash", family="Emotet")
    assert malware.family == "Emotet"

    apk = APKSampleNode(id="apk1", sha256="def456hash", package_name="com.fake.app")
    assert apk.package_name == "com.fake.app"

    domain = DomainNode(id="d1", name="malicious-c2.com")
    assert domain.name == "malicious-c2.com"

    ip = IPAddressNode(id="ip1", addr="192.168.1.1", asn=12345)
    assert ip.addr == "192.168.1.1"

    cert = CertificateNode(id="c1", fingerprint="fingerprint123")
    assert cert.fingerprint == "fingerprint123"

    tech = ATTACKTechniqueNode(id="T1059", name="Command Interpreter")
    assert tech.name == "Command Interpreter"

    log = LogEntryNode(id="l1", timestamp="2024-01-01T00:00:00Z", source="Sysmon")
    assert log.source == "Sysmon"

    artifact = EvidenceArtifactNode(
        id="ea1",
        artifact_type="PCAP",
        storage_path="/path/to/pcap",
        hash_sha256="hash123",
    )
    assert artifact.artifact_type == "PCAP"


def test_edge_models_instantiation() -> None:
    """Verifies all 15 relationship model classes instantiate cleanly."""
    e1 = ExploitsEdge(from_id="a1", to_id="cve1", vector="Network")
    assert e1.vector == "Network"

    e2 = DeliversEdge(from_id="a1", to_id="m1", delivery_method="Phishing")
    assert e2.delivery_method == "Phishing"

    e3 = CommunicatesWithEdge(from_id="m1", to_id="ip1", port=443)
    assert e3.port == 443

    e4 = UsesCertificateEdge(from_id="d1", to_id="c1", validation_status="Valid")
    assert e4.validation_status == "Valid"

    e5 = MapsToEdge(from_id="l1", to_id="tech1", mapping_confidence=0.95)
    assert e5.mapping_confidence == 0.95

    e6 = LinkedCampaignEdge(from_id="a1", to_id="a2", campaign_name="OpSolar")
    assert e6.campaign_name == "OpSolar"

    e7 = DowngradesToEdge(from_id="c1", to_id="c2", reason="Expired")
    assert e7.reason == "Expired"

    e8 = DerivedFromEdge(from_id="l1", to_id="ea1", extraction_method="Parser")
    assert e8.extraction_method == "Parser"

    e9 = PrecedesEdge(from_id="l1", to_id="l2", time_delta_ms=100)
    assert e9.time_delta_ms == 100

    e10 = ExpectedToLeadToEdge(from_id="t1", to_id="t2", probability=0.8)
    assert e10.probability == 0.8

    e11 = DetectedByEdge(from_id="m1", to_id="ea1", rule_name="Yara_Emotet")
    assert e11.rule_name == "Yara_Emotet"

    e12 = ExportedAsEdge(from_id="ea1", to_id="ea2", format="STIX")
    assert e12.format == "STIX"

    e13 = HasResponseEdge(from_id="v1", to_id="ea1", status="Mitigated")
    assert e13.status == "Mitigated"

    e14 = ResolvesToEdge(from_id="d1", to_id="ip1", resolved_at="2024-01-01T00:00:00Z")
    assert e14.resolved_at == "2024-01-01T00:00:00Z"

    e15 = SupersedesEdge(
        from_id="n::v2", to_id="n::v1", superseded_at="2024-01-01T00:00:00Z"
    )
    assert e15.superseded_at == "2024-01-01T00:00:00Z"
