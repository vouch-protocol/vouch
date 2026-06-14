"""vouch-crewai: a CrewAI tool that issues Vouch Credentials.

Thin distribution wrapping vouch.integrations.crewai. It exists so the tool can
be installed and listed on its own while the implementation stays
single-sourced in the vouch-protocol package.
"""

from vouch.integrations.crewai.tool import VouchCrewTools, sign_request

__all__ = ["sign_request", "VouchCrewTools"]
__version__ = "0.1.0"
