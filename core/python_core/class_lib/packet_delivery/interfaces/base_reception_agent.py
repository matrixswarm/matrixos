from abc import ABC, abstractmethod
from typing import Any
from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketProcessorBase
class BaseReceptionAgent(ABC):
    """Interface for all reception agent implementations (filesystem, redis, etc)."""

    @abstractmethod
    def set_crypto_handler(self, crypto_handler: PacketProcessorBase):
        pass

    @abstractmethod
    def set_metadata(self, metadata: dict):
        """Sets optional reception parameters (e.g. file_ext, TTL, stream name). Returns self."""
        pass

    @abstractmethod
    def set_location(self, loc: dict):
        """Sets the base location (e.g., file path or Redis structure). Returns self."""
        pass

    @abstractmethod
    def set_identifier(self, name: str):
        """Overrides the default filename: filename_prefix_timestamp."""
        pass

    @abstractmethod
    def set_address(self, ids: list):
        """Sets target agent universal_ids. Returns self."""
        pass

    @abstractmethod
    def set_drop_zone(self, drop: dict):
        """Sets the internal drop path (e.g., 'incoming', 'log'). Returns self."""
        pass

    @abstractmethod
    def get_agent_type(self) -> str:
        """Returns the agent type as string: 'filesystem', 'redis', etc."""
        pass

    @abstractmethod
    def get_error_success(self) -> int:
        """Returns 0 if successful, 1 if error occurred."""
        pass

    @abstractmethod
    def get_error_success_msg(self) -> str:
        """Returns human-readable reason for last failure."""
        pass

    @abstractmethod
    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        pass

    @abstractmethod
    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        pass

    @abstractmethod
    def receive(self):
        """Performs the receive operation. Returns a wrapped packet or None."""
        pass
