from abc import ABC, abstractmethod
from typing import Dict, Any

class PacketProcessorBase(ABC):
    """Interface for all inbound packet processors (decrypt/plaintext/etc)."""

    @abstractmethod
    def prepare_for_processing(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processes raw incoming file_data. Returns decrypted or parsed content."""
        pass

    @abstractmethod
    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        pass

    @abstractmethod
    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        pass

class PacketEncryptorBase(ABC):
    """Interface for all outbound encryption strategies."""

    @abstractmethod
    def prepare_for_delivery(self, packet_obj: Any) -> Dict[str, Any]:
        """Wraps packet_obj in encryption envelope. Returns safe dict to write."""
        pass