from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def utc_now():
    return datetime.now(timezone.utc)


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
        nullable=False,
    )

    domain: Mapped[str] = mapped_column(
        String(253),
        index=True,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    modules: Mapped[list["ModuleRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class ModuleRecord(Base):
    __tablename__ = "module_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scan_records.scan_id"),
        index=True,
        nullable=False,
    )

    module_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    completed_at: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    data: Mapped[dict | list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    scan: Mapped["ScanRecord"] = relationship(
        back_populates="modules",
    )


class FindingRecord(Base):
    __tablename__ = "finding_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scan_records.scan_id"),
        index=True,
        nullable=False,
    )

    finding_type: Mapped[str] = mapped_column(
        String(80),
        index=True,
        nullable=False,
    )

    indicator: Mapped[str] = mapped_column(
        String(500),
        index=True,
        nullable=False,
    )

    score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    level: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    source: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    details: Mapped[dict | list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    scan: Mapped["ScanRecord"] = relationship(
        back_populates="findings",
    )

class ScheduledScanRecord(Base):
    """Configurazione persistente di una scansione periodica."""

    __tablename__ = "scheduled_scan_records"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), index=True, nullable=False)
    selected_modules: Mapped[list] = mapped_column(JSON, nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_scan_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ScreenshotRecord(Base):
    """Metadati persistenti di uno screenshot acquisito con autorizzazione."""

    __tablename__ = "screenshot_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(253), index=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    screenshot_path: Mapped[str] = mapped_column(Text, nullable=False)
    page_title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    page_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    comparison_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    similarity_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    assessment: Mapped[str | None] = mapped_column(String(100), nullable=True)


    phash_distance: Mapped[int | None] = mapped_column(Integer, nullable=True)
