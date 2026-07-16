from __future__ import annotations

from pydantic import BaseModel, Field  # type: ignore[import]
from typing import List, Optional
from typing_extensions import TypedDict
from datetime import datetime


# ═══════════════════════════════════════════════════════════════════
# sFlow Telemetry (ClickHouse row model)
# ═══════════════════════════════════════════════════════════════════

class SflowTelemetry(BaseModel):
    """Pydantic data model mapping the owl_bronze.sflowsPremit and sflowsPostmit ClickHouse schema."""

    # --- Core Timestamps & Identifiers ---
    # Timestamp the packet was received by the collector in nanoseconds (UInt64)
    time_received_ns: int
    # Sequence number of the sFlow datagram to detect packet drops (UInt32)
    sequence_num: int
    # The sampling rate configured on the device (e.g., 1000 for 1-in-1000) (Int32)
    sampling_rate: int
    # IP address of the device/router generating the sFlow records (String)
    sampler_address: str

    # --- L2 (Data Link Layer) ---
    # Total length of the frame in bytes (UInt32)
    frame_length: int
    # Source MAC address (String)
    src_mac: str
    # Destination MAC address (String)
    dst_mac: str
    # Human-readable Ethernet protocol type (e.g., 'IPv4', 'IPv6') (LowCardinality String)
    ethernet_type: str
    # Length of the Ethernet header in bytes (UInt16)
    ethernet_length: int

    # --- L3 (Network Layer) ---
    # Source IP address (String)
    src_addr: str
    # Destination IP address (String)
    dst_addr: str
    # Length of the IP header in bytes (UInt8)
    ip_header_len: int
    # IP Type of Service (ToS) / DSCP field (UInt8)
    ip_tos: int
    # IP Time to Live (TTL) (UInt8)
    ip_ttl: int
    # IP fragmentation flags (UInt8)
    ip_flags: int
    # Total length of the IP packet in bytes (UInt16)
    ip_len: int
    # IANA Protocol Number (e.g., 6 for TCP, 17 for UDP) (UInt8)
    ip_proto_no: int
    # IP header checksum (UInt16)
    ip_checksum: int
    # Fragment offset for fragmented packets (UInt16)
    fragment_offset: int
    # Flag indicating if more fragments follow (UInt8)
    more_fragments: int
    # Human-readable protocol name matching ip_proto_no (LowCardinality String)
    protocol: str

    # --- L4 (Transport Layer) ---
    # Length of UDP header in bytes (UInt16)
    udp_header_len: int
    # Length of TCP header in bytes (UInt16)
    tcp_header_len: int
    # TCP Acknowledgment Number (UInt32)
    tcp_ack_no: int
    # TCP Sequence Number (UInt32)
    tcp_seq_no: int
    # TCP Window Size (UInt16)
    window_size: int
    # Source port (UInt16, ClickHouse T64)
    src_port: int
    # Destination port (UInt16, ClickHouse T64)
    dst_port: int
    # List of raw TCP flag integer values (Array of UInt16)
    tcp_flags: List[int] = Field(default_factory=list)
    # List of human-readable TCP flags (e.g., ['SYN', 'ACK']) (Array of String)
    tcp_flags_named: List[str] = Field(default_factory=list)

    # --- ICMP Fields ---
    # ICMP message type (UInt8)
    icmp_type: int
    # ICMP message code (UInt8)
    icmp_code: int
    # Combined human-readable ICMP type/code name (String)
    icmp_type_code_name: str
    # ICMP Identifier for echo requests/replies (UInt16)
    icmp_id: int
    # ICMP Sequence number (UInt16)
    icmp_seq: int

    # --- Payload & Interfaces ---
    # Hex representation or snippet of the packet payload (String)
    payload: str
    # SNMP ifIndex of the input interface (UInt32)
    in_if: int
    # SNMP ifIndex of the output interface (UInt32)
    out_if: int

    # --- Encapsulation & Decoded Stacks ---
    # List of parsed layer protocols (e.g., ['Ethernet', 'IPv4', 'TCP']) (Array of String)
    layer_stack: List[str]
    # Sizes of the respective layers in the stack (Array of Int32)
    layer_size: List[int]
    # 802.1Q VLAN ID (UInt16)
    vlan_id: int = 0
    # Boolean flag indicating if this packet is an IP fragment (Bool)
    is_fragment: bool = False

    # --- DNS Specifics ---
    # Parsed DNS answers, questions, authorities, and additionals (Arrays of String)
    dns_answers: List[str] = Field(default_factory=list)
    dns_questions: List[str] = Field(default_factory=list)
    dns_authorities: List[str] = Field(default_factory=list)
    dns_additionals: List[str] = Field(default_factory=list)

    # --- ESP/GRE Tunnels ---
    # Encapsulating Security Payload (ESP) and Generic Routing Encapsulation (GRE) decodes
    esp_seq: int = 0
    esp_spi: int = 0
    gre_version: int = 0
    gre_protocol: int = 0
    gre_protocol_named: str = ""
    gre_checksum: int = 0
    gre_seq_no: int = 0
    gre_ack_no: int = 0
    gre_checksum_present: bool = False
    gre_key_present: bool = False
    gre_key: int = 0
    gre_seq_present: bool = False
    gre_ack_present: bool = False
    gre_routing_present: bool = False
    gre_strict_source_route: bool = False
    gre_recursion_control: int = 0
    gre_flags: int = 0
    gre_offset: int = 0

    # --- Database Metadata ---
    # Time the row was inserted into the ClickHouse materialized view (DateTime)
    time_inserted: Optional[datetime] = None

    # --- BGP ASN & Geo-Enrichment ---
    # Autonomous System Number (ASN) of the source and destination (UInt32)
    src_asn: int = 0
    dst_asn: int = 0
    # Geographic mapping coordinates
    src_latitude: float = 0.0
    src_longitude: float = 0.0
    dst_latitude: float = 0.0
    dst_longitude: float = 0.0
    # Geographic mapping locations (LowCardinality String)
    src_city: str = ""
    src_country: str = ""
    src_continent: str = ""
    dst_city: str = ""
    dst_country: str = ""
    dst_continent: str = ""


# ═══════════════════════════════════════════════════════════════════
# Agent State — Typed Classes
# ═══════════════════════════════════════════════════════════════════

class PeakWindow(BaseModel):
    """A single detected traffic peak."""
    peak_id: str                  # e.g. "overall_bps_1", "lon_pps_3"
    scope: str                    # "overall" or SC name
    metric: str                   # "bps" or "pps"
    start_ts: datetime
    end_ts: datetime
    total_bps: float
    total_pps: float


class BreakdownEntry(BaseModel):
    """One row in a peak breakdown."""
    value: str                    # e.g. "TCP", "443", "lon"
    bps: float = 0.0
    pps: float = 0.0
    share_pct: float = 0.0       # % of total in this peak
    baseline_share_pct: float | None = None
    delta_pct: float | None = None  # % change vs baseline; None = "new"


class PeakBreakdown(BaseModel):
    """Full decomposition of a single peak across four dimensions."""
    peak_id: str
    overall_bps: float = 0.0
    overall_pps: float = 0.0
    total_bps_delta_pct: float | None = None
    total_pps_delta_pct: float | None = None
    by_sc: list[BreakdownEntry] = Field(default_factory=list)
    by_ethernet_type: list[BreakdownEntry] = Field(default_factory=list)
    by_protocol: list[BreakdownEntry] = Field(default_factory=list)
    by_dst_port: list[BreakdownEntry] = Field(default_factory=list)


class PooledBaseline(BaseModel):
    """6-day pooled baseline rates and per-dimension shares."""
    total_bytes: float = 0.0
    total_packets: float = 0.0
    num_days: int = 0
    baseline_bps: float = 0.0
    baseline_pps: float = 0.0
    protocol_shares: dict[str, float] = Field(default_factory=dict)   # lowercased protocol → share
    dst_port_shares: dict[str, float] = Field(default_factory=dict)   # port string → share
    sc_shares: dict[str, float] = Field(default_factory=dict)         # sc_name → share
    raw_profiles: list[dict] = Field(default_factory=list)


class TrafficSnapshot(BaseModel):
    """Final output: all views + per-peak fields, ready to render."""
    detection_target: str
    scrub_centers: list[str] = Field(default_factory=list)
    baseline: PooledBaseline | None = None
    bps_peaks: dict[str, list[PeakWindow]] = Field(default_factory=dict)  # scope → peaks
    pps_peaks: dict[str, list[PeakWindow]] = Field(default_factory=dict)
    peak_breakdowns: dict[str, PeakBreakdown] = Field(default_factory=dict)


class TrafficIntelState(TypedDict, total=False):
    """LangGraph state for the traffic analysis agent."""
    # Inputs
    detection_target: str
    scrub_centers: list[str]
    window_hours: int                          # how far back to query sflowsPostmit (default 24)

    # Resolution
    device_ips: dict[str, list[str]]       # sc_name → [sampler_address, ...]

    # Baseline (Cassandra, 6 trailing days)
    baseline: PooledBaseline | None

    # Live peaks (ClickHouse, configurable window via window_hours)
    # Keyed by scope: "overall" + each SC name
    peaks_bps: dict[str, list[PeakWindow]]
    peaks_pps: dict[str, list[PeakWindow]]

    # Per-peak decomposition
    peak_breakdowns: dict[str, PeakBreakdown]  # keyed by peak_id

    # Final output
    output: TrafficSnapshot | None