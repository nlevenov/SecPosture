"""Read-only collectors and fact gathering."""

from .base import Collector, CommandResult, FileStat, HostFacts
from .gather import gather, host_info
from .local import LocalCollector
from .ssh import SSHCollector

__all__ = ["Collector", "CommandResult", "FileStat", "HostFacts", "LocalCollector",
           "SSHCollector", "gather", "host_info"]
