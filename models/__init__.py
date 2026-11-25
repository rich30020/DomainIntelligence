"""Expose core domain and IOC models through a compact package API."""

from models.domain import Domain
from models.ioc import IOC

__all__ = ["Domain", "IOC"]