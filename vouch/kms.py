import time
from typing import List, Dict

class RotatingKeyProvider:
    """
    Enterprise Key Management for Vouch.
    Automatically rotates the active signing key based on time.
    """
    
    def __init__(self, keys: List[Dict[str, str]], rotation_interval_hours: int = 24):
        self.keys = keys
        self.interval = rotation_interval_hours * 3600
        
    def get_active_key(self) -> Dict[str, str]:
        current_epoch = int(time.time())
        index = (current_epoch // self.interval) % len(self.keys)
        return self.keys[index]
