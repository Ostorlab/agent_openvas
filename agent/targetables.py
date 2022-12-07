"""Definitions of targetable assets by the openvas agent."""
import dataclasses
from typing import Optional


@dataclasses.dataclass
class DomainTarget:
    """Domain name target dataclass definition."""

    name: str


@dataclasses.dataclass
class IPTarget:
    """IP address target dataclass definition."""

    name: str
    version: int
    mask: Optional[str] = None
    port: Optional[str] = None
    schema: Optional[str] = None
