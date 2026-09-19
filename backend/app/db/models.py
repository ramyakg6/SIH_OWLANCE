"""SQLAlchemy ORM Models for OwLance"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from app.db.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    """A registered account. Scans and history are scoped to a user."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    # bcrypt hash. The plaintext password is never stored or logged.
    password_hash = Column(String(255), nullable=False)
    org_name = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)


class ScanHistory(Base):
    """
    One row per completed scan, so the score trend is a real series rather
    than a decorative sparkline.
    """
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    org_score = Column(Integer, nullable=False)
    findings_count = Column(Integer, nullable=False, default=0)
    assets_count = Column(Integer, nullable=False, default=0)
    data_confidence = Column(String(20), nullable=False, default="high")
    scanned_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)


class AuditEvent(Base):
    """
    Append-only, hash-chained audit log.

    Each row stores the hash of the previous row, so altering or deleting any
    historical entry breaks every hash that follows it. That makes the log
    tamper-evident: verification is a single pass recomputing the chain.
    """
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id = Column(String(36), nullable=True, index=True)
    action = Column(String(64), nullable=False)
    detail = Column(String(512), nullable=False, default="")
    meta = Column(JSON, nullable=False, default=dict)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    prev_hash = Column(String(64), nullable=False, default="")
    entry_hash = Column(String(64), nullable=False, default="")


class ConsentLog(Base):
    """Logs user authorization and active scan consent."""
    __tablename__ = "consent_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    requester_ip = Column(String(45), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    consent_version = Column(String(20), nullable=False, default="1.0")
    active_scan_allowed = Column(Boolean, nullable=False, default=False)


class Asset(Base):
    """Discovered attack surface asset."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    asset_name = Column(String(255), nullable=False)
    asset_type = Column(String(64), nullable=False)  # Primary Domain, Web Application, Mail Server, etc.
    discovery_method = Column(String(64), nullable=False)  # CT Logs, DNS Enum, Seed
    discovered_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    tech_stack = Column(JSON, nullable=False, default=dict)  # Detected technologies, DNS records, headers
    open_ports = Column(JSON, nullable=False, default=list)  # List of integer open ports
    status = Column(String(32), nullable=False, default="monitored")  # monitored, unverified, unmonitored
    discovery_confidence = Column(Float, nullable=False, default=0.90)  # 0.0 to 1.0

    # Relationships
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assets_scan_domain", "scan_id", "domain"),
    )


class Finding(Base):
    """Vulnerabilities, misconfigurations, and hygiene exposures associated with assets."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(32), nullable=True)
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    cwe_id = Column(String(32), nullable=True)
    is_kev = Column(Boolean, nullable=False, default=False)
    exposure_multiplier = Column(Float, nullable=False, default=1.0)  # Standardized 1.0 for P0 external
    asset_criticality_weight = Column(Float, nullable=False, default=1.0)
    final_risk_score = Column(Float, nullable=False, default=0.0)

    # UI presentation & optimization metrics (matching OwLance.jsx FINDINGS shape)
    issue = Column(String(255), nullable=False)
    short = Column(String(64), nullable=False)
    severity = Column(String(20), nullable=False, default="Medium")  # Critical, High, Medium, Low
    category = Column(String(32), nullable=False, default="Web App")  # Email, Web App, Network, Identity, Cloud
    confidence = Column(Integer, nullable=False, default=85)  # 0-100
    cost = Column(Integer, nullable=False, default=0)  # Remediation cost in ₹
    reduction = Column(Integer, nullable=False, default=10)  # % Risk reduction
    eal = Column(Float, nullable=False, default=5.0)  # Expected Annual Loss in Lakhs
    impact = Column(Integer, nullable=False, default=3)  # 1-5
    likelihood = Column(Integer, nullable=False, default=3)  # 1-5

    # Resilience & data availability tracking
    data_unavailable = Column(Boolean, nullable=False, default=False)
    is_stale_cache = Column(Boolean, nullable=False, default=False)

    # Relationship
    asset = relationship("Asset", back_populates="findings")

    # Removed manual index to avoid duplicate creation; SQLAlchemy will create necessary index via foreign key.


class CacheEntry(Base):
    """Persistent 24-hour cache for external threat intel and discovery queries."""
    __tablename__ = "cache_entries"

    cache_key = Column(String(512), primary_key=True)
    cached_data = Column(JSON, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
