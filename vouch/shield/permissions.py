"""
Vouch Shield - Capability-Based Permissions.

Enforces fine-grained permissions per DID using capability-based security.
"""

import os
import json
import logging
from typing import Optional, Dict, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class PermissionLevel(Enum):
    """Permission levels for resource access."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    FULL = "full"


class NetworkLevel(Enum):
    """Network access levels."""
    NONE = "none"
    INTERNAL = "internal"
    OUTBOUND = "outbound"
    FULL = "full"


class ShellLevel(Enum):
    """Shell execution levels."""
    NONE = "none"
    SANDBOXED = "sandboxed"
    FULL = "full"


@dataclass
class Capabilities:
    """Capability set for a DID."""
    filesystem: PermissionLevel = PermissionLevel.NONE
    network: NetworkLevel = NetworkLevel.NONE
    shell: ShellLevel = ShellLevel.NONE
    custom: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary."""
        result = {
            "filesystem": self.filesystem.value,
            "network": self.network.value,
            "shell": self.shell.value,
        }
        result.update(self.custom)
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "Capabilities":
        """Create from dictionary."""
        return cls(
            filesystem=PermissionLevel(data.get("filesystem", "none")),
            network=NetworkLevel(data.get("network", "none")),
            shell=ShellLevel(data.get("shell", "none")),
            custom={k: v for k, v in data.items() 
                   if k not in ("filesystem", "network", "shell")},
        )


# Tool to capability mapping
TOOL_REQUIREMENTS: Dict[str, Dict[str, str]] = {
    # Filesystem tools
    "read_file": {"filesystem": "read"},
    "write_file": {"filesystem": "write"},
    "delete_file": {"filesystem": "full"},
    "list_directory": {"filesystem": "read"},
    "create_directory": {"filesystem": "write"},
    
    # Network tools
    "http_get": {"network": "outbound"},
    "http_post": {"network": "outbound"},
    "fetch": {"network": "outbound"},
    "websocket": {"network": "full"},
    
    # Shell tools
    "run_command": {"shell": "full"},
    "execute_shell": {"shell": "full"},
    "bash": {"shell": "full"},
    "subprocess": {"shell": "sandboxed"},
}


class PermissionManager:
    """
    Manages capability-based permissions for DIDs.
    
    Example:
        >>> pm = PermissionManager()
        >>> pm.set_capabilities("did:vouch:agent", Capabilities(
        ...     filesystem=PermissionLevel.READ,
        ...     network=NetworkLevel.OUTBOUND
        ... ))
        >>> allowed, reason = pm.check_permission("did:vouch:agent", "read_file")
        >>> assert allowed
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the permission manager.
        
        Args:
            config_path: Path to capabilities config file.
        """
        self._capabilities: Dict[str, Capabilities] = {}
        self._default = Capabilities()
        self._config_path = config_path or self._default_config_path()
        
        self._load_config()
    
    def _default_config_path(self) -> str:
        """Get default config path."""
        vouch_dir = Path.home() / ".vouch"
        vouch_dir.mkdir(exist_ok=True)
        return str(vouch_dir / "capabilities.json")
    
    def _load_config(self) -> None:
        """Load capabilities from config file."""
        try:
            if os.path.exists(self._config_path):
                with open(self._config_path, "r") as f:
                    config = json.load(f)
                    
                    if "default" in config:
                        self._default = Capabilities.from_dict(config["default"])
                    
                    for did, caps_dict in config.get("capabilities", {}).items():
                        self._capabilities[did] = Capabilities.from_dict(caps_dict)
                    
                    logger.info(f"Loaded capabilities for {len(self._capabilities)} DIDs")
        except Exception as e:
            logger.warning(f"Could not load capabilities config: {e}")
    
    def save_config(self) -> None:
        """Save capabilities to config file."""
        config = {
            "default": self._default.to_dict(),
            "capabilities": {
                did: caps.to_dict() 
                for did, caps in self._capabilities.items()
            },
        }
        
        with open(self._config_path, "w") as f:
            json.dump(config, f, indent=2)
    
    def get_capabilities(self, did: str) -> Capabilities:
        """Get capabilities for a DID."""
        return self._capabilities.get(did, self._default)
    
    def set_capabilities(self, did: str, capabilities: Capabilities) -> None:
        """Set capabilities for a DID."""
        self._capabilities[did] = capabilities
        logger.info(f"Set capabilities for {did}")
    
    def set_default(self, capabilities: Capabilities) -> None:
        """Set default capabilities for unknown DIDs."""
        self._default = capabilities
    
    def check_permission(self, did: str, tool: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a DID has permission to use a tool.
        
        Args:
            did: The DID requesting permission.
            tool: The tool name to check.
            
        Returns:
            Tuple of (allowed, reason if denied).
        """
        caps = self.get_capabilities(did)
        requirements = TOOL_REQUIREMENTS.get(tool.lower())
        
        if requirements is None:
            # Unknown tool - deny by default for safety
            return False, f"Unknown tool: {tool}"
        
        # Check each requirement
        for resource, required in requirements.items():
            if resource == "filesystem":
                if not self._check_level(
                    caps.filesystem.value, required, 
                    ["none", "read", "write", "full"]
                ):
                    return False, f"Insufficient filesystem permission: requires {required}, has {caps.filesystem.value}"
            
            elif resource == "network":
                if not self._check_level(
                    caps.network.value, required,
                    ["none", "internal", "outbound", "full"]
                ):
                    return False, f"Insufficient network permission: requires {required}, has {caps.network.value}"
            
            elif resource == "shell":
                if not self._check_level(
                    caps.shell.value, required,
                    ["none", "sandboxed", "full"]
                ):
                    return False, f"Insufficient shell permission: requires {required}, has {caps.shell.value}"
        
        return True, None
    
    def _check_level(self, has: str, needs: str, levels: list) -> bool:
        """Check if 'has' level is sufficient for 'needs' level."""
        try:
            return levels.index(has) >= levels.index(needs)
        except ValueError:
            return False
    
    def register_tool(self, tool: str, requirements: Dict[str, str]) -> None:
        """Register a custom tool with its permission requirements."""
        TOOL_REQUIREMENTS[tool.lower()] = requirements
