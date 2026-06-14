"""vouch-safetensors: embed Vouch Credentials in .safetensors headers.

Thin distribution wrapping vouch.integrations.safetensors. It exists so the
safetensors signing helpers can be installed and listed on their own while the
implementation stays single-sourced in the vouch-protocol package.
"""

from vouch.integrations.safetensors import (
    read_embedded_credential,
    sign_safetensors,
    tensor_data_digest,
    verify_safetensors,
)

__all__ = [
    "sign_safetensors",
    "verify_safetensors",
    "read_embedded_credential",
    "tensor_data_digest",
]
__version__ = "0.1.0"
