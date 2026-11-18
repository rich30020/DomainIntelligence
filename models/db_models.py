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