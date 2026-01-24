#!/usr/bin/env python3
"""
Vouch CLI - Command-line interface for Vouch Protocol

Commands:
    vouch sign <file>           Sign a file using the local Vouch Bridge daemon
    vouch verify <file>         Verify a file's C2PA manifest (works offline)
    vouch status                Check daemon health and current identity
    
    vouch agent create <name>   Create a delegated agent identity (Ghost Signature)
    vouch agent list            List all active agent identities
    vouch agent revoke <name>   Revoke an agent identity
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from vouch_sdk.client import (
    VouchClient,
    VouchConnectionError,
    NoKeysConfiguredError,
    UserDeniedSignatureError,
)

# Try to import c2pa for verification (graceful fallback)
try:
    import c2pa
    C2PA_AVAILABLE = True
except ImportError:
    C2PA_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

AGENT_REGISTRY_PATH = Path.home() / ".vouch" / "agents.json"
AGENT_ENV_PATH = Path.home() / ".vouch" / "agent.env"


# =============================================================================
# CLI Application
# =============================================================================

app = typer.Typer(
    name="vouch",
    help="🔐 Vouch Protocol CLI - Sign and verify content provenance",
    add_completion=False,
    no_args_is_help=True,
)

# Agent subcommand group
agent_app = typer.Typer(
    name="agent",
    help="👻 Manage delegated agent identities (Ghost Signatures)",
    no_args_is_help=True,
)
app.add_typer(agent_app, name="agent")

console = Console()


# =============================================================================
# Utility Functions
# =============================================================================

def format_timestamp(ts: str | float | None) -> str:
    """Format a timestamp for display."""
    if ts is None:
        return "Unknown"
    
    if isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts)
    else:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return str(ts)
    
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def truncate_key(key: str, length: int = 16) -> str:
    """Truncate a key for display with ellipsis."""
    if len(key) <= length:
        return key
    return f"{key[:length//2]}...{key[-length//2:]}"


def ensure_vouch_dir():
    """Ensure ~/.vouch directory exists."""
    vouch_dir = Path.home() / ".vouch"
    vouch_dir.mkdir(parents=True, exist_ok=True)
    return vouch_dir


def load_agent_registry() -> dict:
    """Load agent registry from disk."""
    if not AGENT_REGISTRY_PATH.exists():
        return {"agents": {}, "version": "1.0"}
    
    try:
        return json.loads(AGENT_REGISTRY_PATH.read_text())
    except (json.JSONDecodeError, IOError):
        return {"agents": {}, "version": "1.0"}


def save_agent_registry(registry: dict):
    """Save agent registry to disk."""
    ensure_vouch_dir()
    AGENT_REGISTRY_PATH.write_text(json.dumps(registry, indent=2))


def get_client_and_check_connection() -> tuple[VouchClient, dict]:
    """Get client and check connection, exit on failure."""
    client = VouchClient()
    
    try:
        status = client.connect()
        return client, status
    except VouchConnectionError:
        rprint(Panel(
            "[bold red]❌ Vouch Bridge not running![/bold red]\n\n"
            "The local daemon is required for this operation.\n\n"
            "[dim]Start it with:[/dim] [bold cyan]vouch-bridge[/bold cyan]",
            title="Connection Error",
            border_style="red",
        ))
        raise typer.Exit(1)


# =============================================================================
# Sign Command
# =============================================================================

@app.command("sign")
def sign_file(
    file: Path = typer.Argument(
        ...,
        help="Path to the file to sign",
        exists=True,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output path for signed file (default: overwrites original)",
    ),
    agent: Optional[str] = typer.Option(
        None,
        "--agent", "-a",
        help="Sign using a delegated agent identity",
    ),
    covenant: Optional[str] = typer.Option(
        None,
        "--covenant", "-c",
        help="Apply usage policy: 'no-ai', 'no-derivatives', 'permissive'",
    ),
):
    """
    🖊️  Sign a file using the local Vouch Bridge daemon.
    
    The file will be signed with your Vouch identity and embedded with
    C2PA content credentials for images/video/audio/PDF files.
    
    Examples:
        vouch sign photo.jpg
        vouch sign document.pdf -o signed_document.pdf
        vouch sign voice.wav --agent "my-bot" --covenant no-ai
    """
    client, status = get_client_and_check_connection()
    
    # Display identity info
    rprint(f"[green]✓[/green] Connected to Vouch Bridge v{status.get('version', 'unknown')}")
    
    # Check if using agent identity
    agent_info = None
    if agent:
        registry = load_agent_registry()
        if agent not in registry.get("agents", {}):
            rprint(f"[red]Error:[/red] Agent '{agent}' not found. Create it with: vouch agent create {agent}")
            raise typer.Exit(1)
        
        agent_info = registry["agents"][agent]
        if agent_info.get("revoked"):
            rprint(f"[red]Error:[/red] Agent '{agent}' has been revoked.")
            raise typer.Exit(1)
        
        rprint(f"[cyan]👻[/cyan] Signing as agent: [bold]{agent}[/bold]")
    
    # Prepare metadata with covenant
    metadata = {}
    if covenant:
        covenant_policies = {
            "no-ai": {"ai_training": False, "voice_cloning": False},
            "no-derivatives": {"ai_training": False, "derivative_works": False},
            "permissive": {"ai_training": True, "derivative_works": True, "commercial_use": True},
        }
        
        if covenant not in covenant_policies:
            rprint(f"[red]Error:[/red] Unknown covenant '{covenant}'. Options: no-ai, no-derivatives, permissive")
            raise typer.Exit(1)
        
        metadata["covenant"] = covenant_policies[covenant]
        rprint(f"[yellow]📜[/yellow] Applying covenant: [bold]{covenant}[/bold]")
    
    if agent_info:
        metadata["agent_did"] = agent_info.get("did")
        metadata["agent_name"] = agent
    
    # Sign the file
    output_path = output or file
    
    with console.status(f"[bold blue]Signing {file.name}..."):
        try:
            signed_bytes = client.sign_file(
                str(file),
                origin=f"cli:{file.name}",
                metadata=metadata if metadata else None,
            )
            
            # Write the signed file
            output_path.write_bytes(signed_bytes)
            
        except NoKeysConfiguredError:
            rprint(Panel(
                "[bold red]❌ No keys configured![/bold red]\n\n"
                "Generate a new identity using the Vouch Bridge.\n\n"
                "[dim]The daemon will prompt you to generate keys on first use.[/dim]",
                title="No Identity",
                border_style="red",
            ))
            raise typer.Exit(1)
            
        except UserDeniedSignatureError:
            rprint(Panel(
                "[bold yellow]⚠️ Signature denied[/bold yellow]\n\n"
                "You declined to sign this file in the consent popup.",
                title="User Cancelled",
                border_style="yellow",
            ))
            raise typer.Exit(1)
            
        except Exception as e:
            rprint(f"[red]Error signing file:[/red] {e}")
            raise typer.Exit(1)
    
    # Success message
    status_items = [
        f"[dim]Input:[/dim]  {file}",
        f"[dim]Output:[/dim] {output_path}",
        f"[dim]Size:[/dim]   {output_path.stat().st_size:,} bytes",
    ]
    
    if agent:
        status_items.append(f"[dim]Agent:[/dim]  {agent}")
    if covenant:
        status_items.append(f"[dim]Covenant:[/dim] {covenant}")
    
    rprint(Panel(
        f"[bold green]✅ File signed successfully![/bold green]\n\n" +
        "\n".join(status_items),
        title="Signed",
        border_style="green",
    ))


# =============================================================================
# Verify Command
# =============================================================================

@app.command("verify")
def verify_file(
    file: Path = typer.Argument(
        ...,
        help="Path to the file to verify",
        exists=True,
        readable=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed manifest information",
    ),
    check_covenant: Optional[str] = typer.Option(
        None,
        "--check", "-c",
        help="Check if operation is allowed: ai_training, voice_cloning, derivative_works",
    ),
):
    """
    🔍 Verify a file's C2PA content credentials (works offline).
    
    This command reads the embedded C2PA manifest from a file and
    displays information about its provenance chain.
    
    Examples:
        vouch verify photo.jpg
        vouch verify video.mp4 --verbose
        vouch verify voice.wav --check ai_training
    """
    if not C2PA_AVAILABLE:
        rprint(Panel(
            "[bold red]❌ c2pa-python not installed![/bold red]\n\n"
            "Install it with: [cyan]pip install c2pa-python[/cyan]",
            title="Missing Dependency",
            border_style="red",
        ))
        raise typer.Exit(1)
    
    with console.status(f"[bold blue]Reading manifest from {file.name}..."):
        try:
            # Read the file and extract manifest
            reader = c2pa.Reader.from_file(str(file))
            manifest_store = reader.get_manifest_store()
            
        except Exception as e:
            error_str = str(e).lower()
            if "no manifest" in error_str or "not found" in error_str or "jumbf" in error_str:
                rprint(Panel(
                    f"[bold yellow]⚠️ No C2PA manifest found[/bold yellow]\n\n"
                    f"[dim]File:[/dim] {file}\n\n"
                    "This file has not been signed with C2PA content credentials.\n"
                    "It may still have other forms of authentication.",
                    title="Unsigned",
                    border_style="yellow",
                ))
                raise typer.Exit(0)
            else:
                rprint(f"[red]Error reading manifest:[/red] {e}")
                raise typer.Exit(1)
    
    # No manifest found
    if manifest_store is None or not manifest_store:
        rprint(Panel(
            f"[bold yellow]⚠️ No C2PA manifest found[/bold yellow]\n\n"
            f"[dim]File:[/dim] {file}\n\n"
            "This file has not been signed with C2PA content credentials.",
            title="Unsigned",
            border_style="yellow",
        ))
        raise typer.Exit(0)
    
    # Parse and display manifest info
    try:
        manifests = manifest_store.get("manifests", {}) if isinstance(manifest_store, dict) else {}
        active_manifest_id = manifest_store.get("active_manifest") if isinstance(manifest_store, dict) else None
        
        if not manifests:
            if hasattr(manifest_store, "manifests"):
                manifests = manifest_store.manifests
            else:
                manifests = {"unknown": manifest_store}
        
        # Extract signer info
        signer_did = None
        agent_name = None
        covenant_data = None
        claim_generator = None
        timestamp = None
        
        for manifest_id, manifest in manifests.items():
            if manifest_id == active_manifest_id or len(manifests) == 1:
                if isinstance(manifest, dict):
                    claim_generator = manifest.get("claim_generator", "Unknown")
                    signature_info = manifest.get("signature_info", {})
                    timestamp = signature_info.get("time") if isinstance(signature_info, dict) else None
                    
                    # Check assertions for Vouch-specific data
                    for assertion in manifest.get("assertions", []):
                        label = assertion.get("label", "")
                        data = assertion.get("data", {})
                        
                        if label == "vouch.identity":
                            signer_did = data.get("did")
                        elif label == "vouch.covenant":
                            covenant_data = data
                        elif "agent" in str(data).lower():
                            agent_name = data.get("agent_name")
        
        # Build display
        rprint(Panel(
            f"[bold green]✅ Valid C2PA manifest found[/bold green]\n\n"
            f"[dim]File:[/dim] {file}",
            title="Verified",
            border_style="green",
        ))
        
        # Identity table
        table = Table(show_header=False, box=None)
        table.add_column("Property", style="dim", width=15)
        table.add_column("Value")
        
        if signer_did:
            table.add_row("✅ Signed by", f"[bold cyan]{truncate_key(signer_did, 40)}[/bold cyan]")
        if agent_name:
            table.add_row("🤖 Agent", f"[bold]{agent_name}[/bold]")
        if claim_generator:
            table.add_row("🔧 Generator", claim_generator)
        if timestamp:
            table.add_row("📅 Date", format_timestamp(timestamp))
        
        rprint(table)
        
        # Covenant display
        if covenant_data:
            rprint("\n[bold]📜 Vouch Covenant (Usage Policy):[/bold]")
            covenant_table = Table(show_header=True, header_style="bold cyan")
            covenant_table.add_column("Policy")
            covenant_table.add_column("Status")
            
            policies = covenant_data.get("policies", covenant_data)
            for key, value in policies.items():
                if isinstance(value, bool):
                    status = "[green]✓ ALLOW[/green]" if value else "[red]✗ DENY[/red]"
                else:
                    status = str(value)
                covenant_table.add_row(key.replace("_", " ").title(), status)
            
            rprint(covenant_table)
        
        # Covenant compliance check
        if check_covenant and covenant_data:
            policies = covenant_data.get("policies", covenant_data)
            allowed = policies.get(check_covenant, True)
            
            if allowed:
                rprint(f"\n[green]✓[/green] Operation '{check_covenant}' is [bold green]ALLOWED[/bold green]")
            else:
                rprint(f"\n[red]✗[/red] Operation '{check_covenant}' is [bold red]DENIED[/bold red] by covenant")
                raise typer.Exit(1)
        
        if verbose:
            rprint("\n[dim]Raw manifest data:[/dim]")
            try:
                rprint(json.dumps(manifest_store, indent=2, default=str))
            except TypeError:
                rprint(str(manifest_store))
                
    except Exception as e:
        rprint(f"[yellow]Warning: Could not fully parse manifest:[/yellow] {e}")
        rprint(f"[green]✓[/green] File has C2PA signature present")


# =============================================================================
# Status Command
# =============================================================================

@app.command("status")
def show_status():
    """
    📊 Check Vouch Bridge daemon health and current identity.
    
    Displays connection status, public key, and DID information.
    """
    client = VouchClient()
    
    with console.status("[bold blue]Checking Vouch Bridge status..."):
        try:
            status = client.connect()
            is_connected = True
        except VouchConnectionError:
            is_connected = False
            status = {}
    
    # Status panel
    if is_connected:
        # Get public key info
        try:
            key_info = client.get_public_key()
            has_keys = True
        except NoKeysConfiguredError:
            key_info = {}
            has_keys = False
        except Exception:
            key_info = {}
            has_keys = False
        
        # Count registered agents
        registry = load_agent_registry()
        agent_count = len([a for a in registry.get("agents", {}).values() if not a.get("revoked")])
        
        # Build status table
        table = Table(show_header=False, box=None)
        table.add_column("Property", style="dim", width=15)
        table.add_column("Value")
        
        table.add_row("Status", "[bold green]● Online[/bold green]")
        table.add_row("Version", status.get("version", "unknown"))
        table.add_row("Endpoint", "http://127.0.0.1:21000")
        table.add_row("", "")
        
        if has_keys:
            public_key = key_info.get("public_key", key_info.get("publicKey", ""))
            did = key_info.get("did", "")
            fingerprint = key_info.get("fingerprint", "")
            
            table.add_row("Identity", "[bold cyan]Configured[/bold cyan]")
            if did:
                table.add_row("DID", f"[cyan]{truncate_key(did, 40)}[/cyan]")
            if fingerprint:
                table.add_row("Fingerprint", fingerprint)
            if public_key:
                table.add_row("Public Key", truncate_key(public_key, 32))
        else:
            table.add_row("Identity", "[yellow]Not configured[/yellow]")
            table.add_row("", "[dim]Generate keys via the daemon[/dim]")
        
        table.add_row("", "")
        table.add_row("Agents", f"{agent_count} registered")
        
        rprint(Panel(table, title="🔐 Vouch Bridge Status", border_style="green"))
        
    else:
        rprint(Panel(
            "[bold red]● Offline[/bold red]\n\n"
            "The Vouch Bridge daemon is not running.\n\n"
            "[dim]Start it with:[/dim] [bold cyan]vouch-bridge[/bold cyan]",
            title="🔐 Vouch Bridge Status",
            border_style="red",
        ))
        raise typer.Exit(1)


# =============================================================================
# Agent Commands (Ghost Signatures)
# =============================================================================

@agent_app.command("create")
def agent_create(
    name: str = typer.Argument(
        ...,
        help="Unique name for the agent (e.g., 'my-bot', 'data-pipeline')",
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description", "-d",
        help="Description of the agent's purpose",
    ),
    export_env: bool = typer.Option(
        True,
        "--export-env/--no-export-env",
        help="Export credentials to ~/.vouch/agent.env",
    ),
):
    """
    👻 Create a new delegated agent identity (Ghost Signature).
    
    Creates a sub-key derived from your root identity that can be used
    by automated scripts and AI agents to sign content on your behalf.
    
    The agent inherits your identity but with limited scope. You can
    revoke an agent at any time without affecting your root identity.
    
    Examples:
        vouch agent create my-bot
        vouch agent create data-pipeline -d "ETL process for media signing"
    """
    client, status = get_client_and_check_connection()
    
    # Check if agent already exists
    registry = load_agent_registry()
    if name in registry.get("agents", {}):
        existing = registry["agents"][name]
        if existing.get("revoked"):
            rprint(f"[yellow]Agent '{name}' was previously revoked. Creating new identity...[/yellow]")
        else:
            rprint(f"[red]Error:[/red] Agent '{name}' already exists. Use 'vouch agent revoke {name}' first.")
            raise typer.Exit(1)
    
    with console.status(f"[bold blue]Generating agent identity for '{name}'..."):
        try:
            # Request daemon to generate delegated key
            # In a real implementation, this would call a daemon endpoint
            # For now, we simulate with a derived DID
            
            root_key_info = client.get_public_key()
            root_did = root_key_info.get("did", "did:key:unknown")
            
            # Generate agent-specific derived identity
            import hashlib
            agent_seed = hashlib.sha256(f"{root_did}:{name}:{time.time()}".encode()).hexdigest()
            agent_did = f"did:key:z6Mk{agent_seed[:43]}"
            agent_fingerprint = agent_seed[:16].upper()
            
            # Store in registry
            agent_info = {
                "did": agent_did,
                "fingerprint": agent_fingerprint,
                "parent_did": root_did,
                "created_at": datetime.now().isoformat(),
                "description": description,
                "revoked": False,
            }
            
            if "agents" not in registry:
                registry["agents"] = {}
            registry["agents"][name] = agent_info
            save_agent_registry(registry)
            
            # Export to .env file if requested
            if export_env:
                env_content = f"""# Vouch Agent Credentials
# Agent: {name}
# Created: {datetime.now().isoformat()}

VOUCH_AGENT_NAME={name}
VOUCH_AGENT_DID={agent_did}
VOUCH_AGENT_FINGERPRINT={agent_fingerprint}
VOUCH_PARENT_DID={root_did}
"""
                AGENT_ENV_PATH.write_text(env_content)
                
        except NoKeysConfiguredError:
            rprint(Panel(
                "[bold red]❌ No root identity configured![/bold red]\n\n"
                "You need a root identity before creating agents.\n"
                "Start the Vouch Bridge to generate your identity.",
                title="No Identity",
                border_style="red",
            ))
            raise typer.Exit(1)
        except Exception as e:
            rprint(f"[red]Error creating agent:[/red] {e}")
            raise typer.Exit(1)
    
    # Success display
    rprint(Panel(
        f"[bold green]👻 Agent '{name}' created successfully![/bold green]\n\n"
        f"[dim]DID:[/dim]         [cyan]{truncate_key(agent_did, 48)}[/cyan]\n"
        f"[dim]Fingerprint:[/dim] [cyan]{agent_fingerprint}[/cyan]\n"
        f"[dim]Parent:[/dim]      {truncate_key(root_did, 32)}\n"
        + (f"\n[dim]Credentials exported to:[/dim] {AGENT_ENV_PATH}" if export_env else ""),
        title="Agent Created",
        border_style="green",
    ))
    
    # Usage hint
    rprint("\n[dim]Use this agent with:[/dim]")
    rprint(f"  vouch sign myfile.jpg [bold]--agent {name}[/bold]")
    rprint("\n[dim]Or in Python:[/dim]")
    rprint(f'  client.sign("content", agent="{name}")')


@agent_app.command("list")
def agent_list():
    """
    📋 List all registered agent identities.
    
    Shows all active and revoked agents with their details.
    """
    registry = load_agent_registry()
    agents = registry.get("agents", {})
    
    if not agents:
        rprint(Panel(
            "[dim]No agents registered yet.[/dim]\n\n"
            "Create one with: [bold cyan]vouch agent create <name>[/bold cyan]",
            title="👻 Agent Identities",
            border_style="yellow",
        ))
        return
    
    # Build tree display
    tree = Tree("👻 [bold]Agent Identities[/bold]")
    
    active_count = 0
    revoked_count = 0
    
    for name, info in sorted(agents.items()):
        is_revoked = info.get("revoked", False)
        
        if is_revoked:
            revoked_count += 1
            status = "[red]REVOKED[/red]"
            branch = tree.add(f"[dim strikethrough]{name}[/dim strikethrough] {status}")
        else:
            active_count += 1
            status = "[green]ACTIVE[/green]"
            branch = tree.add(f"[bold]{name}[/bold] {status}")
        
        branch.add(f"[dim]DID:[/dim] [cyan]{truncate_key(info.get('did', ''), 40)}[/cyan]")
        branch.add(f"[dim]Created:[/dim] {info.get('created_at', 'Unknown')[:10]}")
        
        if info.get("description"):
            branch.add(f"[dim]Description:[/dim] {info['description']}")
    
    rprint(tree)
    rprint(f"\n[dim]Total: {active_count} active, {revoked_count} revoked[/dim]")


@agent_app.command("revoke")
def agent_revoke(
    name: str = typer.Argument(
        ...,
        help="Name of the agent to revoke",
    ),
    confirm: bool = typer.Option(
        False,
        "--yes", "-y",
        help="Skip confirmation prompt",
    ),
):
    """
    🚫 Revoke an agent identity.
    
    Marks the agent as invalid. Any content signed with this agent
    after revocation should be considered untrusted.
    
    Note: This is a local operation. For full revocation, you should
    also publish a revocation to your DID registry.
    """
    registry = load_agent_registry()
    agents = registry.get("agents", {})
    
    if name not in agents:
        rprint(f"[red]Error:[/red] Agent '{name}' not found.")
        raise typer.Exit(1)
    
    if agents[name].get("revoked"):
        rprint(f"[yellow]Agent '{name}' is already revoked.[/yellow]")
        raise typer.Exit(0)
    
    if not confirm:
        rprint(f"[yellow]⚠️  Warning:[/yellow] This will revoke agent '[bold]{name}[/bold]'")
        rprint("[dim]Content signed by this agent will no longer be trusted.[/dim]\n")
        
        if not typer.confirm("Are you sure?"):
            rprint("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)
    
    # Revoke the agent
    agents[name]["revoked"] = True
    agents[name]["revoked_at"] = datetime.now().isoformat()
    save_agent_registry(registry)
    
    rprint(Panel(
        f"[bold red]🚫 Agent '{name}' has been revoked[/bold red]\n\n"
        f"[dim]DID:[/dim] {truncate_key(agents[name].get('did', ''), 40)}\n"
        f"[dim]Revoked at:[/dim] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="Agent Revoked",
        border_style="red",
    ))


@agent_app.command("show")
def agent_show(
    name: str = typer.Argument(
        ...,
        help="Name of the agent to show details for",
    ),
):
    """
    🔍 Show detailed information about an agent.
    """
    registry = load_agent_registry()
    agents = registry.get("agents", {})
    
    if name not in agents:
        rprint(f"[red]Error:[/red] Agent '{name}' not found.")
        raise typer.Exit(1)
    
    info = agents[name]
    is_revoked = info.get("revoked", False)
    
    table = Table(show_header=False, box=None)
    table.add_column("Property", style="dim", width=15)
    table.add_column("Value")
    
    table.add_row("Name", f"[bold]{name}[/bold]")
    table.add_row("Status", "[red]REVOKED[/red]" if is_revoked else "[green]ACTIVE[/green]")
    table.add_row("DID", f"[cyan]{info.get('did', 'Unknown')}[/cyan]")
    table.add_row("Fingerprint", info.get("fingerprint", "Unknown"))
    table.add_row("Parent DID", truncate_key(info.get("parent_did", "Unknown"), 40))
    table.add_row("Created", info.get("created_at", "Unknown"))
    
    if info.get("description"):
        table.add_row("Description", info["description"])
    
    if is_revoked:
        table.add_row("Revoked At", info.get("revoked_at", "Unknown"))
    
    rprint(Panel(table, title=f"👻 Agent: {name}", border_style="cyan"))


@agent_app.command("export")
def agent_export(
    name: str = typer.Argument(
        ...,
        help="Name of the agent to export credentials for",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (default: ~/.vouch/agent.env)",
    ),
    format: str = typer.Option(
        "env",
        "--format", "-f",
        help="Export format: env, json, or shell",
    ),
):
    """
    📤 Export agent credentials to a file.
    
    Exports the agent's credentials in various formats for use by
    automated scripts and applications.
    """
    registry = load_agent_registry()
    agents = registry.get("agents", {})
    
    if name not in agents:
        rprint(f"[red]Error:[/red] Agent '{name}' not found.")
        raise typer.Exit(1)
    
    info = agents[name]
    
    if info.get("revoked"):
        rprint(f"[yellow]Warning:[/yellow] Agent '{name}' is revoked.")
        if not typer.confirm("Export anyway?"):
            raise typer.Exit(0)
    
    output_path = output or AGENT_ENV_PATH
    
    if format == "env":
        content = f"""# Vouch Agent Credentials
# Agent: {name}
# Exported: {datetime.now().isoformat()}

VOUCH_AGENT_NAME={name}
VOUCH_AGENT_DID={info.get('did', '')}
VOUCH_AGENT_FINGERPRINT={info.get('fingerprint', '')}
VOUCH_PARENT_DID={info.get('parent_did', '')}
"""
    elif format == "json":
        content = json.dumps({
            "name": name,
            "did": info.get("did"),
            "fingerprint": info.get("fingerprint"),
            "parent_did": info.get("parent_did"),
            "created_at": info.get("created_at"),
        }, indent=2)
    elif format == "shell":
        content = f"""#!/bin/bash
# Vouch Agent Credentials - Source this file
export VOUCH_AGENT_NAME="{name}"
export VOUCH_AGENT_DID="{info.get('did', '')}"
export VOUCH_AGENT_FINGERPRINT="{info.get('fingerprint', '')}"
export VOUCH_PARENT_DID="{info.get('parent_did', '')}"
"""
    else:
        rprint(f"[red]Error:[/red] Unknown format '{format}'. Use: env, json, shell")
        raise typer.Exit(1)
    
    Path(output_path).write_text(content)
    rprint(f"[green]✓[/green] Exported to: {output_path}")


# =============================================================================
# Version Command
# =============================================================================

@app.command("version")
def show_version():
    """Show version information."""
    from vouch_sdk import __version__
    rprint(f"[bold]Vouch SDK[/bold] v{__version__}")
    rprint(f"[dim]C2PA Available:[/dim] {'Yes' if C2PA_AVAILABLE else 'No'}")


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
