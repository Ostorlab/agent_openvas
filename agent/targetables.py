"""Definitions of targetable assets by the openvas agent."""

import dataclasses


@dataclasses.dataclass
class DomainTarget:
    """Domain name target dataclass definition."""

    name: str


@dataclasses.dataclass
class IPTarget:
    """IP address target dataclass definition."""

    name: str
    version: int
    mask: str | None = None
    port: str | None = None
    schema: str | None = None
