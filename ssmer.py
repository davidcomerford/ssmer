#!/usr/bin/env python3
"""A terminal UI for AWS SSM shell sessions and port forwarding to EC2 instances.

Prerequisites: AWS CLI v2, the Session Manager plugin, and credentials that
allow DescribeInstances and StartSession.
"""

from __future__ import annotations

import argparse
import contextlib
import curses
import errno
import itertools
import json
import math
import os
import queue
import random
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable, Sequence
from typing import TextIO

__version__ = "0.1.0"

DEFAULT_REMOTE_PORT = "3389"
DEFAULT_LOCAL_PORT = "43389"
# The region picker's choices; SSMER_REGIONS (comma-separated) replaces them.
# Every region in the commercial `aws` partition: the favourites, pinned to
# the top of the picker so it still opens on eu-west-1, then the rest
# alphabetically.
FAVOURITE_REGIONS = ("eu-west-1", "eu-west-2", "ap-southeast-2", "ap-northeast-1", "ap-northeast-3")
REGIONS = FAVOURITE_REGIONS + (
    "af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-2", "ap-south-1", "ap-south-2",
    "ap-southeast-1", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-6",
    "ap-southeast-7", "ca-central-1", "ca-west-1", "eu-central-1", "eu-central-2", "eu-north-1",
    "eu-south-1", "eu-south-2", "eu-west-3", "il-central-1", "me-central-1", "me-south-1",
    "mx-central-1", "sa-east-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
)
# Where each region is, shown beside its code and searched along with it.
REGION_NAMES = {
    "af-south-1": "Cape Town", "ap-east-1": "Hong Kong", "ap-east-2": "Taipei",
    "ap-northeast-1": "Tokyo", "ap-northeast-2": "Seoul", "ap-northeast-3": "Osaka",
    "ap-south-1": "Mumbai", "ap-south-2": "Hyderabad", "ap-southeast-1": "Singapore",
    "ap-southeast-2": "Sydney", "ap-southeast-3": "Jakarta", "ap-southeast-4": "Melbourne",
    "ap-southeast-5": "Malaysia", "ap-southeast-6": "New Zealand", "ap-southeast-7": "Thailand",
    "ca-central-1": "Canada Central", "ca-west-1": "Calgary", "eu-central-1": "Frankfurt",
    "eu-central-2": "Zurich", "eu-north-1": "Stockholm", "eu-south-1": "Milan", "eu-south-2": "Spain",
    "eu-west-1": "Ireland", "eu-west-2": "London", "eu-west-3": "Paris", "il-central-1": "Tel Aviv",
    "me-central-1": "UAE", "me-south-1": "Bahrain", "mx-central-1": "Mexico", "sa-east-1": "São Paulo",
    "us-east-1": "N. Virginia", "us-east-2": "Ohio", "us-west-1": "N. California", "us-west-2": "Oregon",
}
# The picker's headings, after Favourites, and the region prefixes under each.
# Regions outside REGION_NAMES (GovCloud, China, ...) are listed under "Other".
REGION_GROUPS = (
    ("Europe", ("eu-",)),
    ("Asia Pacific", ("ap-",)),
    ("Americas", ("us-", "ca-", "mx-", "sa-")),
    ("Middle East & Africa", ("me-", "il-", "af-")),
)
REGION_PICKER_TOP = 5  # the first list row, below the title and instructions
NON_TERMINATED_STATES = ("pending", "running", "shutting-down", "stopping", "stopped")
NOT_MANAGED = "Not managed"
# A mid grey from the 256-colour ramp (#8a8a8a): ~6:1 against a dark
# background, where colour 8 ("bright black") renders near-black and is barely
# legible.  A_DIM stands in on terminals without the extended palette.
GREY_COLOR = 245

# Rows 0-3 are the k9s-style header (context beside a grid of key bindings),
# 4 the top edge of the list's frame and 5 the column header.
HEADER_ROWS = 4
LIST_TOP = HEADER_ROWS + 2
# The key grid's (key, action) cells, filled column by column.
MAIN_KEYS = (
    ("Enter", "Connect/Forward"), ("/", "Search"), ("g", "Region"),
    ("d", "Disconnect"), ("D", "Disconnect all"), ("r", "Refresh"),
    ("q", "Quit"),
)
# How narrow the header's context values may be cut before key columns go.
MIN_CONTEXT_WIDTH = 24
SEARCH_KEYS = (("↑/↓", "Move"), ("Enter", "Select"), ("Esc", "Clear"))
QUIT_BUTTONS = {"quit": "Quit", "disconnect": "Quit + disconnect", "cancel": "Cancel"}
POLL_INTERVAL_MS = 200
# The list is fetched off the main thread, so polling can be brisk enough for
# the spinner to look smooth while a load is in flight.
LOADING_POLL_MS = 80
LOADING_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
# The radar drawn in the empty list while a region's instances load.  Braille
# packs 2×4 dots into each character cell, and those dots come out roughly
# square, so a radar twice as many columns wide as it is rows tall is round.
BRAILLE_DOTS = ((0x01, 0x08), (0x02, 0x10), (0x04, 0x20), (0x40, 0x80))  # [dot row][dot column]
RADAR_MIN_ROWS = 4
RADAR_MAX_ROWS = 11
RADAR_REVOLUTION_S = 2.4
RADAR_TRAIL = 8  # ghost beams fading out behind the sweep
RADAR_TRAIL_STEP = 0.09  # radians between ghost beams
RADAR_BLIPS = 5
# 256-colour ramp for radar brightness 0 (rings) to 3 (the beam).
RADAR_COLORS = (238, 28, 34, 46)
PORT_DIGITS = 5  # 65535 is the highest port
NAME_WIDTH = 32  # the NAME column, which search highlights are drawn within
INSTANCE_ID_WIDTH = 19  # "i-" plus 17 hex digits, the longest EC2 ID
# Characters after which a match counts as the start of a word in a name.
WORD_SEPARATORS = " -_./:"
# session-manager-plugin prints these once the local port is listening.  Until
# then the AWS CLI may still be calling StartSession, or on its way to failing.
FORWARD_READY_MARKERS = ("opened for sessionId", "Waiting for connections")
# The plugin retries silently when it cannot reach the session endpoint, so a
# tunnel that is still not up by now gets called out rather than left spinning.
CONNECT_WARNING_S = 30
# The kernel's socket tables on Linux; row "st" 0A is TCP_LISTEN.
PROC_TCP_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")

CONNECT = "connect"
PORT_FORWARD = "forward"
# What Enter offers on an instance: (action, hotkey, label, description).
ACTIONS = (
    (CONNECT, "c", "Connect", "Interactive shell session"),
    (PORT_FORWARD, "p", "Port Forward", "Tunnel a remote port to localhost"),
)
# Ctrl+C, Ctrl+\ and Ctrl+Z signal every process in the terminal's foreground
# group.  During a shell session they are meant for the remote shell, which
# the SSM plugin forwards them to.
USER_SIGNALS = (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP)
# EC2 key pairs used to decrypt a Windows instance's Administrator password.
DEFAULT_KEYS_DIR = Path(__file__).resolve().parent / "keys"
# The note shipped in keys/ to show where keys go; it is not a key itself.
KEYS_PLACEHOLDER = "YOUR-EC2-KEYS-HERE.txt"
KEY_PICKER_ROWS = 10
# (environment variable the tool needs, command reading the text on stdin).
CLIPBOARD_COMMANDS = (
    ("WAYLAND_DISPLAY", ("wl-copy",)),
    ("DISPLAY", ("xclip", "-selection", "clipboard")),
    ("DISPLAY", ("xsel", "--clipboard", "--input")),
    (None, ("pbcopy",)),
    (None, ("clip.exe",)),
)


@dataclass(frozen=True)
class Instance:
    instance_id: str
    name: str
    state: str
    instance_type: str
    private_ip: str
    ssm_status: str = NOT_MANAGED
    key_name: str = ""  # the EC2 key pair the instance was launched with
    platform: str = ""  # "Windows" or "Linux"; see platform_family

    @property
    def label(self) -> str:
        name = self.name or "(unnamed)"
        ip = self.private_ip or "no private IP"
        return f"{name:<{NAME_WIDTH}.{NAME_WIDTH}} {self.instance_id:<{INSTANCE_ID_WIDTH}} {self.state:<10} {self.ssm_status:<14} {self.instance_type:<11} {self.platform:<8} {ip}"


@dataclass
class Forward:
    instance: Instance
    remote_port: str
    local_port: str
    process: subprocess.Popen[str]
    # Set once the local port is open: by the output watcher when the plugin
    # says so, or by update_forwards when the port shows up listening.
    connected: bool = False
    # Each transition is announced exactly once, whether the tunnel was
    # stopped on purpose or changed state on its own.
    connect_reported: bool = False
    slow_reported: bool = False
    exit_reported: bool = False
    last_line: str = ""  # the latest output, which usually explains a failure
    started: float = field(default_factory=time.monotonic)
    watcher: threading.Thread | None = None

    @property
    def route(self) -> str:
        return f"localhost:{self.local_port} → {self.instance.instance_id}:{self.remote_port}"


@dataclass(frozen=True)
class Account:
    account_id: str
    arn: str  # the identity the credentials resolve to: a user or assumed role
    alias: str = ""  # the account's IAM alias, its human-readable name when one is set

    @property
    def label(self) -> str:
        return f"{self.alias} ({self.account_id})" if self.alias else self.account_id

    @property
    def identity(self) -> str:
        """Who the credentials act as, short enough for the header.

        The account is shown separately, so this keeps only the ARN's resource
        part: `user/dave` for an IAM user and `admin/dave` for an assumed role,
        whose session name follows the role.  An IAM Identity Center role,
        `AWSReservedSSO_<permission set>_<hash>`, shows as its permission set.
        """
        parts = self.arn.split(":", 5)
        if len(parts) != 6:
            return self.arn
        resource = parts[5]
        if not resource.startswith("assumed-role/"):
            return resource
        role, _, session = resource.removeprefix("assumed-role/").partition("/")
        if role.startswith("AWSReservedSSO_"):
            role = role.removeprefix("AWSReservedSSO_").rpartition("_")[0] or role
        return f"{role}/{session}" if session else role


def aws_command(profile: str | None, region: str | None, *args: str) -> list[str]:
    command = ["aws"]
    if profile:
        command.extend(["--profile", profile])
    if region:
        command.extend(["--region", region])
    return [*command, *args]


def region_choices(region: str | None, configured: str | None = None) -> tuple[str, ...]:
    """Offer the picker's regions, plus any other region the caller asked for.

    `configured` is a comma-separated list (SSMER_REGIONS) that replaces the
    built-in REGIONS.  Without the extra entry a `--region` outside the list
    was silently discarded and the picker fell back to its first region.
    """
    regions = tuple(name for name in (part.strip() for part in (configured or "").split(",")) if name) or REGIONS
    if region and region not in regions:
        return (region, *regions)
    return regions


def group_regions(regions: Sequence[str]) -> list[tuple[str, list[str]]]:
    """Sort the picker's regions under headings, dropping any that end up empty.

    Favourites come first, then the geographic groups, keeping the order the
    regions were given in within each.
    """
    groups: dict[str, list[str]] = {"Favourites": []}
    groups.update((heading, []) for heading, _ in REGION_GROUPS)
    groups["Other"] = []
    for region in regions:
        if region in FAVOURITE_REGIONS:
            heading = "Favourites"
        elif region not in REGION_NAMES:
            heading = "Other"  # us-gov-west-1 shares its prefix with us-east-1
        else:
            heading = next((heading for heading, prefixes in REGION_GROUPS if region.startswith(prefixes)), "Other")
        groups[heading].append(region)
    return [(heading, members) for heading, members in groups.items() if members]


def region_label(region: str, width: int) -> str:
    """The region's code, padded to `width`, and where it is when that is known."""
    name = REGION_NAMES.get(region)
    return f"{region:<{width}}  {name}" if name else region


def get_instances(
    profile: str | None,
    region: str | None,
    warn: Callable[[str], None] | None = None,
) -> list[Instance]:
    """Fetch non-terminated EC2 instances using the caller's AWS CLI context."""
    command = aws_command(
        profile,
        region,
        "ec2",
        "describe-instances",
        "--filters",
        f"Name=instance-state-name,Values={','.join(NON_TERMINATED_STATES)}",
        "--output",
        "json",
    )
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or "AWS CLI returned an unknown error"
        raise RuntimeError(message)

    payload = json.loads(result.stdout)
    ssm_statuses = get_ssm_statuses(profile, region, warn)
    instances: list[Instance] = []
    for reservation in payload.get("Reservations", []):
        for item in reservation.get("Instances", []):
            tags = {tag["Key"]: tag["Value"] for tag in item.get("Tags", []) if "Key" in tag and "Value" in tag}
            instances.append(
                Instance(
                    instance_id=item["InstanceId"],
                    name=tags.get("Name", ""),
                    state=item.get("State", {}).get("Name", "unknown"),
                    instance_type=item.get("InstanceType", ""),
                    private_ip=item.get("PrivateIpAddress", ""),
                    ssm_status=ssm_statuses.get(item["InstanceId"], NOT_MANAGED),
                    key_name=item.get("KeyName", ""),
                    platform=platform_family(item),
                )
            )
    return sorted(instances, key=lambda instance: (instance.name.lower(), instance.instance_id))


def platform_family(item: dict) -> str:
    """Boil a DescribeInstances item's platform down to "Windows" or "Linux".

    `PlatformDetails` names the AMI's billing product, e.g. "Windows with SQL
    Server Standard" or "Red Hat Enterprise Linux"; everything that is not
    Windows runs Linux (macOS instances report "Linux/UNIX" too).  `Platform`
    is only ever set, to "windows", on Windows instances.
    """
    details = item.get("PlatformDetails", "")
    if item.get("Platform") == "windows" or details.startswith("Windows"):
        return "Windows"
    return "Linux" if details else ""


def get_ssm_statuses(
    profile: str | None,
    region: str | None,
    warn: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """Return SSM reachability for managed instances.

    A failure here is not fatal — the instance list is still worth showing —
    but it is reported through `warn` so that every row reading "Not managed"
    is not mistaken for a fleet-wide SSM outage when the real cause is a
    missing ssm:DescribeInstanceInformation permission.
    """
    command = aws_command(profile, region, "ssm", "describe-instance-information", "--output", "json")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        if warn:
            warn(f"SSM status unavailable: {error}")
        return {}
    if result.returncode:
        if warn:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
            warn(f"SSM status unavailable: {detail}")
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        if warn:
            warn("SSM status unavailable: could not parse the AWS CLI response.")
        return {}
    return {
        item["InstanceId"]: item.get("PingStatus", "Unknown")
        for item in payload.get("InstanceInformationList", [])
        if item.get("InstanceId")
    }


def get_account(
    profile: str | None,
    region: str | None,
    warn: Callable[[str], None] | None = None,
) -> Account:
    """Confirm the credentials work and identify the account they belong to.

    Raises RuntimeError when there is no valid session — no credentials, or
    an expired SSO token or assumed role — since nothing else can work then.
    """
    command = aws_command(profile, region, "sts", "get-caller-identity", "--output", "json")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}")
    identity = json.loads(result.stdout)
    return Account(identity.get("Account", ""), identity.get("Arn", ""), get_account_alias(profile, region, warn))


def get_account_alias(
    profile: str | None,
    region: str | None,
    warn: Callable[[str], None] | None = None,
) -> str:
    """The account's IAM alias, or "" when it has none or it cannot be read.

    Like the SSM status, the alias is a nicety: a role without
    iam:ListAccountAliases still gets a working app, with a warning saying why
    only the account number is shown.
    """
    command = aws_command(profile, region, "iam", "list-account-aliases", "--output", "json")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        if warn:
            warn(f"Account alias unavailable: {error}")
        return ""
    if result.returncode:
        if warn:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
            warn(f"Account alias unavailable: {detail}")
        return ""
    try:
        aliases = json.loads(result.stdout).get("AccountAliases", [])
    except json.JSONDecodeError:
        if warn:
            warn("Account alias unavailable: could not parse the AWS CLI response.")
        return ""
    return aliases[0] if aliases else ""


def fuzzy_match(query: str, text: str) -> tuple[int, list[int]] | None:
    """Match `query` against `text` fzf-style, returning (score, matched positions) or None.

    Every query character must appear in `text` in order, ignoring case.  A
    higher score is a better match: contiguous runs and matches at the start
    of a word ("web" in "prod-web-01") count for more, gaps count against.
    """
    needle, haystack = query.lower(), text.lower()
    if not needle:
        return 0, []
    start = haystack.find(needle)
    if start >= 0:
        positions = list(range(start, start + len(needle)))
    else:
        # Find the earliest place the match can end, then walk back from
        # there for the latest start, so the match is as tight as it can be.
        end = -1
        for char in needle:
            end = haystack.find(char, end + 1)
            if end < 0:
                return None
        positions = []
        for char in reversed(needle):
            end = haystack.rfind(char, 0, end + 1)
            positions.append(end)
            end -= 1
        positions.reverse()
    score = 0
    previous: int | None = None
    for position in positions:
        score += 1
        if position == 0 or haystack[position - 1] in WORD_SEPARATORS or (
            text[position].isupper() and text[position - 1].islower()
        ):
            score += 4
        if previous is not None:
            gap = position - previous - 1
            score += 4 if gap == 0 else -min(gap, 2)
        previous = position
    return score, positions


def is_key_candidate(name: str) -> bool:
    """Whether the key browser should offer a file or directory: not hidden, not the placeholder."""
    return not name.startswith(".") and name != KEYS_PLACEHOLDER


def list_key_directory(directory: Path) -> tuple[list[Path], list[Path]]:
    """The subdirectories and files in `directory`, each sorted by name, hidden ones left out.

    Both are empty when the directory is missing or unreadable.
    """
    try:
        entries = [entry for entry in directory.iterdir() if is_key_candidate(entry.name)]
    except OSError:
        return [], []
    def by_name(entry: Path) -> str:
        return entry.name.lower()

    return (
        sorted((entry for entry in entries if entry.is_dir()), key=by_name),
        sorted((entry for entry in entries if entry.is_file()), key=by_name),
    )


def find_key_files(root: Path) -> list[Path]:
    """Every file at any depth under `root`, sorted, skipping hidden ones and the placeholder."""
    found: list[Path] = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if not name.startswith(".")]
        found.extend(Path(directory, name) for name in files if is_key_candidate(name))
    return sorted(found)


def get_admin_password(profile: str | None, region: str | None, instance_id: str, key_file: Path) -> str:
    """Decrypt a Windows instance's Administrator password with its launch key."""
    command = aws_command(
        profile, region, "ec2", "get-password-data", "--instance-id", instance_id,
        "--priv-launch-key", str(key_file), "--output", "json",
    )
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}")
    password = json.loads(result.stdout).get("PasswordData", "").strip()
    if not password:
        # EC2 returns an empty string rather than an error in both cases.
        raise RuntimeError("no password available (not a Windows instance, or it is still being generated)")
    return password


def copy_to_clipboard(text: str) -> str | None:
    """Copy `text` with the first clipboard tool that works, returning its name, or None."""
    for needs, command in CLIPBOARD_COMMANDS:
        if needs and not os.environ.get(needs):
            continue
        if not shutil.which(command[0]):
            continue
        try:
            # xclip and wl-copy stay behind to serve the selection, so their
            # output must not be a pipe that run() would wait on forever.
            result = subprocess.run(
                command, input=text, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if not result.returncode:
            return command[0]
    return None


def valid_port(value: str) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except ValueError:
        return False


def local_port_in_use(port: int) -> bool:
    """Whether something already listens on 127.0.0.1:`port`, where the plugin will listen.

    Probed by binding the way the plugin itself does, with SO_REUSEADDR, so a
    port whose old connections linger in TIME_WAIT still counts as free.  Run
    only before a forward starts: probing later could race the plugin's bind.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            return error.errno == errno.EADDRINUSE
    return False


def listening_ports(tables: Sequence[str] = PROC_TCP_TABLES) -> set[int] | None:
    """Local TCP ports in the LISTEN state, or None where there is no /proc to read.

    Read from the kernel rather than tested by connecting: a connection to a
    tunnel's port would be forwarded to the instance like any other client.
    """
    ports: set[int] = set()
    readable = False
    for table in tables:
        try:
            with open(table) as rows:
                next(rows, None)  # column headings
                for row in rows:
                    fields = row.split()
                    if len(fields) > 3 and fields[3] == "0A":
                        ports.add(int(fields[1].rsplit(":", 1)[1], 16))
        except (OSError, ValueError):
            continue
        readable = True
    return ports if readable else None


def radar_blips(seed: str) -> list[tuple[float, float]]:
    """Fixed (angle, fraction of radius) blips, so each region keeps its own pattern."""
    rng = random.Random(seed)
    return [(rng.uniform(0, 2 * math.pi), rng.uniform(0.3, 0.9)) for _ in range(RADAR_BLIPS)]


def radar_frame(
    cols: int, rows: int, angle: float, blips: Sequence[tuple[float, float]]
) -> list[tuple[str, list[int]]]:
    """Render one radar frame as rows of (braille text, brightness per cell).

    Brightness runs from 0 for the static rings to 3 for the beam, and -1
    marks an empty cell.  `angle` is the beam's heading in radians; with y
    growing downwards, an increasing angle sweeps clockwise.
    """
    width, height = cols * 2, rows * 4
    cx, cy = (width - 1) / 2, (height - 1) / 2
    radius = min(cx, cy)
    bits = [[0] * cols for _ in range(rows)]
    levels = [[-1] * cols for _ in range(rows)]

    def plot(x: float, y: float, level: int) -> None:
        dot_x, dot_y = round(x), round(y)
        if 0 <= dot_x < width and 0 <= dot_y < height:
            row, col = dot_y // 4, dot_x // 2
            bits[row][col] |= BRAILLE_DOTS[dot_y % 4][dot_x % 2]
            levels[row][col] = max(levels[row][col], level)

    steps = max(16, round(2 * math.pi * radius))
    for step in range(steps):
        heading = 2 * math.pi * step / steps
        plot(cx + radius * math.cos(heading), cy + radius * math.sin(heading), 0)
        if step % 3 == 0:  # a dotted range ring at half distance
            plot(cx + radius / 2 * math.cos(heading), cy + radius / 2 * math.sin(heading), 0)

    for ghost in range(RADAR_TRAIL + 1):
        heading = angle - ghost * RADAR_TRAIL_STEP
        level = 3 if ghost == 0 else 2 if ghost <= 2 else 1
        for distance in range(int(radius) + 1):
            plot(cx + distance * math.cos(heading), cy + distance * math.sin(heading), level)

    for heading, fraction in blips:
        # A blip flares as the beam crosses it, then fades over the revolution.
        freshness = 1 - ((angle - heading) % (2 * math.pi)) / (2 * math.pi)
        if freshness < 0.35:
            continue
        level = 3 if freshness > 0.85 else 2 if freshness > 0.6 else 1
        x, y = cx + fraction * radius * math.cos(heading), cy + fraction * radius * math.sin(heading)
        for dx, dy in ((0, 0), (1, 0), (0, 1), (1, 1)):
            plot(x + dx, y + dy, level)

    return [
        ("".join(chr(0x2800 + cell) if cell else " " for cell in row_bits), row_levels)
        for row_bits, row_levels in zip(bits, levels, strict=True)
    ]


def run_interactive(command: list[str]) -> int:
    """Run a command in the foreground of this terminal and return its exit status.

    The keys in USER_SIGNALS reach this process as well as the session, and
    left at their defaults they would raise KeyboardInterrupt, kill or stop
    the TUI underneath the live shell.  They are ignored only after the child
    starts, so it does not inherit that and can still be interrupted before
    the session is up.
    """
    process = subprocess.Popen(command)
    previous = {signum: signal.signal(signum, signal.SIG_IGN) for signum in USER_SIGNALS}
    try:
        return process.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def wait_for_enter(text: str) -> None:
    try:
        input(text)
    except (EOFError, KeyboardInterrupt):
        pass


class App:
    def __init__(
        self, screen: curses.window, profile: str | None, region: str | None, keys_dir: Path = DEFAULT_KEYS_DIR
    ) -> None:
        self.screen = screen
        self.profile = profile
        self.region = region
        self.keys_dir = keys_dir
        self.regions = region_choices(region, os.environ.get("SSMER_REGIONS"))
        self.account: Account | None = None
        self.instances: list[Instance] = []
        self.query = ""
        self.searching = False  # whether keystrokes go to the search box
        # The (instances, query) that `shown` was last filtered from.
        self.filtered_from: tuple[list[Instance], str] | None = None
        self.filtered: list[Instance] = []
        self.match_positions: dict[str, list[int]] = {}
        self.match_attr = curses.A_BOLD | curses.A_UNDERLINE
        self.selected = 0
        self.top = 0
        self.message = "Loading instances…"
        self.forwards: dict[str, Forward] = {}
        self.output: deque[str] = deque(maxlen=200)
        self.output_queue: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.result_queue: queue.SimpleQueue[tuple[int, str, object]] = queue.SimpleQueue()
        # Status messages from password fetches, which run on worker threads.
        self.message_queue: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.loading = False
        self.load_generation = 0
        self.spinner_frame = 0
        self.active_status_attr = curses.A_BOLD
        self.connecting_status_attr = curses.A_BOLD
        self.disconnected_status_attr = curses.A_BOLD
        self.unmanaged_attr = curses.A_DIM
        self.rule_attr = curses.A_DIM
        self.heading_attr = curses.A_BOLD
        self.radar_attrs = (curses.A_DIM, curses.A_DIM, curses.A_NORMAL, curses.A_BOLD)
        self.load_started = time.monotonic()

    def configure_colors(self) -> None:
        """Enable status colours when the current terminal supports them."""
        if not curses.has_colors():
            return
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(8, curses.COLOR_YELLOW, -1)
            curses.init_pair(9, curses.COLOR_CYAN, -1)
            self.active_status_attr |= curses.color_pair(1)
            self.connecting_status_attr |= curses.color_pair(8)
            self.disconnected_status_attr |= curses.color_pair(2)
            self.match_attr |= curses.color_pair(8)
            self.heading_attr |= curses.color_pair(9)
            green = curses.color_pair(1)
            self.radar_attrs = (curses.A_DIM, green | curses.A_DIM, green, green | curses.A_BOLD)
            if curses.COLORS > GREY_COLOR:
                curses.init_pair(3, GREY_COLOR, -1)
                self.unmanaged_attr = curses.color_pair(3)
                self.rule_attr = curses.color_pair(3)
                for pair, color in enumerate(RADAR_COLORS, start=4):
                    curses.init_pair(pair, color, -1)
                ring, faint, trail, beam = (curses.color_pair(pair) for pair in range(4, 8))
                self.radar_attrs = (ring, faint, trail, beam | curses.A_BOLD)
        except curses.error:
            # Colour is a helpful enhancement, not a requirement for running.
            pass

    def addline(self, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        """Write one clipped line, skipping anything off-screen.

        curses raises on out-of-bounds writes, so a terminal shrunk below the
        space the layout wants would otherwise take the whole app down.
        """
        height, width = self.screen.getmaxyx()
        if not 0 <= y < height or not 0 <= x < width - 1:
            return
        try:
            self.screen.addnstr(y, x, text, width - 1 - x, attr)
        except curses.error:
            pass

    def log(self, text: str) -> None:
        """Append a command's output to the bottom panel, one display line at a time."""
        for line in text.splitlines() or [text]:
            if line.strip():
                self.output.append(line.strip())

    def run_version_check(self, command: list[str]) -> None:
        label = " ".join(command)
        self.log(f"$ {label}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.log(result.stdout or result.stderr or f"exit status {result.returncode}")
        except OSError as error:
            self.log(f"{label}: {error}")

    def check_session(self) -> bool:
        """Confirm there is a valid AWS session before anything else is tried.

        Without one every later call fails, each with its own copy of the
        same credentials error.  Returns False when the user quits instead of
        retrying.
        """
        self.screen.timeout(-1)
        try:
            while True:
                self.screen.erase()
                self.addline(0, 0, self.title(), curses.A_BOLD)
                self.addline(2, 0, "Checking the AWS session…", curses.A_DIM)
                self.screen.refresh()
                self.log("$ " + " ".join(aws_command(self.profile, self.region, "sts", "get-caller-identity")))
                try:
                    self.account = get_account(self.profile, self.region, self.log)
                except (RuntimeError, OSError, json.JSONDecodeError) as error:
                    self.log(f"Error: {error}")
                    if not self.show_session_error(str(error)):
                        return False
                    continue
                self.log(f"Account {self.account.label} as {self.account.arn}")
                return True
        finally:
            self.screen.timeout(POLL_INTERVAL_MS)

    def show_session_error(self, error: str) -> bool:
        """Explain why there is no session, returning True to retry and False to quit."""
        profile = f" --profile {self.profile}" if self.profile else ""
        while True:
            self.screen.erase()
            height, width = self.screen.getmaxyx()
            self.addline(0, 0, self.title(), curses.A_BOLD)
            self.addline(2, 0, "No valid AWS session", self.disconnected_status_attr)
            lines = [
                wrapped
                for line in error.splitlines()
                for wrapped in textwrap.wrap(line, max(20, width - 3)) or [""]
            ]
            for row, line in enumerate(lines[: max(0, height - 8)], start=4):
                self.addline(row, 2, line)
            hint_row = 5 + min(len(lines), max(0, height - 8))
            self.addline(hint_row, 0, f"Refresh your credentials (for example: aws sso login{profile}), then retry.", curses.A_DIM)
            self.addline(hint_row + 1, 0, "[r] Retry   [q/Esc] Quit", curses.A_DIM)
            self.screen.refresh()
            key = self.read_key(-1)
            if key in (ord("q"), 27):
                return False
            if key in (ord("r"), curses.KEY_ENTER, 10, 13):
                return True

    def check_dependencies(self) -> None:
        self.run_version_check(["aws", "--version"])
        self.run_version_check(["session-manager-plugin", "--version"])

    def drain_output(self) -> None:
        while True:
            try:
                self.log(self.output_queue.get_nowait())
            except queue.Empty:
                break
        while True:
            try:
                self.message = self.message_queue.get_nowait()
            except queue.Empty:
                return

    def watch_output(self, stream: TextIO, forward: Forward) -> None:
        """Read a tunnel's output outside the curses event loop, noting when it connects."""
        try:
            for line in stream:
                text = line.rstrip()
                if text:
                    forward.last_line = text
                if any(marker in text for marker in FORWARD_READY_MARKERS):
                    forward.connected = True
                self.output_queue.put(f"[{forward.local_port} → {forward.instance.instance_id}] {text}")
        finally:
            stream.close()

    def update_forwards(self) -> None:
        """Announce each tunnel as it connects, and again when it goes away.

        A running AWS CLI process is not yet a working tunnel, so a forward
        counts as connected only once its local port is open: the plugin says
        so in its output, or the port shows up listening in the kernel's
        socket table.  The port was free when the forward started, so the
        listener is the tunnel's own.  One that exits first failed to
        connect; one that exits later dropped.
        """
        waiting = [f for f in self.forwards.values() if not f.connected and f.process.poll() is None]
        listening = listening_ports() if waiting else None
        now = time.monotonic()
        for forward in waiting:
            if listening is not None and int(forward.local_port) in listening:
                forward.connected = True
            elif now - forward.started >= CONNECT_WARNING_S and not forward.slow_reported:
                forward.slow_reported = True
                detail = f" Last output: {forward.last_line}" if forward.last_line else ""
                self.log(f"{forward.route} is still not connected after {CONNECT_WARNING_S}s.")
                self.message = f"{forward.route} still not connected after {CONNECT_WARNING_S}s; d cancels it.{detail}"
        for forward in self.forwards.values():
            if forward.connected and not forward.connect_reported:
                forward.connect_reported = True
                self.log(f"{forward.route} connected.")
                self.message = f"Connected {forward.route}."
            status = forward.process.poll()
            if status is None or forward.exit_reported:
                continue
            forward.exit_reported = True
            if forward.watcher:
                # Let the watcher catch up on the final output, which usually
                # holds the reason the tunnel ended.
                forward.watcher.join(timeout=0.5)
            if forward.connected:
                self.log(f"{forward.route} disconnected (exit status {status}).")
                self.message = f"{forward.route} disconnected (exit status {status})."
            else:
                reason = f": {forward.last_line}" if forward.last_line else "."
                self.log(f"{forward.route} failed to connect (exit status {status}).")
                self.message = f"{forward.route} failed to connect (exit status {status}){reason}"

    def poll_interval(self) -> int:
        return LOADING_POLL_MS if self.loading else POLL_INTERVAL_MS

    def start_reload(self) -> None:
        """Fetch the instance list on a worker thread.

        Doing this on the main thread froze the whole UI — spinner included —
        for as long as the two AWS CLI calls took.
        """
        self.load_generation += 1
        self.loading = True
        self.load_started = time.monotonic()
        self.spinner_frame = 0
        self.message = "Loading instances…"
        threading.Thread(
            target=self.load_instances,
            args=(self.load_generation, self.profile, self.region),
            daemon=True,
        ).start()

    def load_instances(self, generation: int, profile: str | None, region: str | None) -> None:
        """Worker body: hand the outcome back through the result queue.

        OSError covers the AWS CLI simply not being installed, which used to
        escape reload() and take the application down.
        """
        try:
            self.result_queue.put((generation, "ok", get_instances(profile, region, self.output_queue.put)))
        except (RuntimeError, OSError, json.JSONDecodeError) as error:
            self.result_queue.put((generation, "error", error))

    def drain_load_results(self) -> None:
        while True:
            try:
                generation, outcome, payload = self.result_queue.get_nowait()
            except queue.Empty:
                return
            if generation != self.load_generation:
                continue  # a region switch or refresh superseded this fetch
            self.loading = False
            if outcome == "error":
                self.instances = []
                self.message = f"Could not load instances: {payload}"
                continue
            self.instances = list(payload)  # type: ignore[arg-type]
            self.selected = min(self.selected, max(0, len(self.shown) - 1))
            self.message = f"{len(self.instances)} instance(s)."

    def select_region(self) -> bool:
        """Let the user choose a region before loading instances.

        The regions are grouped under headings; "/" filters them by code or
        place name, and Enter picks the highlighted one, so "/", "tok" and
        Enter reach Tokyo.  Returns False when the user cancels the
        application from this screen.
        """
        width = max(map(len, self.regions))
        labels = {region: region_label(region, width) for region in self.regions}
        query = ""
        searching = False
        selected: str | None = self.region if self.region in self.regions else None
        top = 0
        self.screen.timeout(-1)
        try:
            while True:
                rows, matched = self.region_rows(labels, query)
                choices = [region for _, region in rows if region]
                if selected not in choices:
                    selected = choices[0] if choices else None  # the best match
                top = self.draw_region_picker(rows, matched, selected, width, query if searching else None, top)

                key = self.read_key(-1)
                index = choices.index(selected) if selected else 0
                page = max(1, self.screen.getmaxyx()[0] - REGION_PICKER_TOP)
                if key in (curses.KEY_ENTER, 10, 13):
                    if selected:
                        self.region = selected
                        return True
                elif key == curses.KEY_UP or (key == ord("k") and not searching):
                    selected = choices[max(0, index - 1)] if choices else None
                elif key == curses.KEY_DOWN or (key == ord("j") and not searching):
                    selected = choices[min(len(choices) - 1, index + 1)] if choices else None
                elif key == curses.KEY_PPAGE:
                    selected = choices[max(0, index - page)] if choices else None
                elif key == curses.KEY_NPAGE:
                    selected = choices[min(len(choices) - 1, index + page)] if choices else None
                elif searching:
                    # The search edits like the instance list's: Esc drops it,
                    # keeping the highlighted region, and Backspace on an
                    # empty search just leaves it.
                    if key == 27:
                        query, searching = "", False
                        self.set_cursor(0)
                    elif key in (curses.KEY_BACKSPACE, curses.KEY_DC, 127, 8):
                        if query:
                            query, selected = query[:-1], None
                        else:
                            searching = False
                            self.set_cursor(0)
                    elif key == 21:  # Ctrl+U, as in a shell
                        query, selected = "", None
                    elif 32 <= key < 127:
                        query, selected = query + chr(key), None
                elif key in (ord("q"), 27):
                    return False
                elif key == ord("/"):
                    searching = True
                    self.set_cursor(1)
        finally:
            self.set_cursor(0)
            self.screen.timeout(POLL_INTERVAL_MS)

    def region_rows(
        self, labels: dict[str, str], query: str
    ) -> tuple[list[tuple[str, str | None]], dict[str, list[int]]]:
        """The picker's (text, region) rows, region None for a heading, and each match's positions.

        Without a search the regions sit under their headings; with one, the
        matches are listed best first with no headings.
        """
        if not query:
            rows: list[tuple[str, str | None]] = []
            for heading, members in group_regions(self.regions):
                rows.append((heading, None))
                rows.extend((labels[region], region) for region in members)
            return rows, {}
        matches = []
        for region in self.regions:
            match = fuzzy_match(query, labels[region])
            if match:
                matches.append((match[0], region, match[1]))
        matches.sort(key=lambda match: -match[0])  # stable, so ties keep the picker's order
        return [(labels[region], region) for _, region, _ in matches], {region: positions for _, region, positions in matches}

    def draw_region_picker(
        self,
        rows: Sequence[tuple[str, str | None]],
        matched: dict[str, list[int]],
        selected: str | None,
        width: int,
        query: str | None,
        top: int,
    ) -> int:
        """Draw the region picker scrolled to keep `selected` on screen, returning the new scroll offset.

        `query` is the search being typed, or None when the search is closed.
        The full list is taller than a typical terminal, so the rows below
        the instructions scroll; a region first in its group brings its
        heading into view with it.
        """
        height, _ = self.screen.getmaxyx()
        visible = max(1, height - REGION_PICKER_TOP)
        row = next((index for index, (_, region) in enumerate(rows) if region == selected), 0)
        first = row - 1 if row > 0 and rows[row - 1][1] is None else row
        if first < top:
            top = first
        elif row >= top + visible:
            top = row - visible + 1
        top = max(0, min(top, len(rows) - visible))

        self.screen.erase()
        self.addline(0, 0, self.title(), curses.A_BOLD)
        self.addline(2, 0, "Select an AWS region", curses.A_BOLD)
        if query is None:
            self.addline(3, 0, "↑/↓ or j/k move · / search · Enter select · q/Esc quit", curses.A_DIM)
        else:
            self.addline(3, 0, f"/{query}")
            self.addline(3, len(query) + 3, "Enter select · Esc clear", curses.A_DIM)
        for y, (text, region) in enumerate(rows[top : top + visible], start=REGION_PICKER_TOP):
            if region is None:
                self.addline(y, 2, text, self.heading_attr)
                continue
            attr = curses.A_REVERSE if region == selected else curses.A_NORMAL
            self.addline(y, 4, text, attr)
            if region != selected:
                self.addline(y, 4 + width, text[width:], self.rule_attr)  # the place name, in grey
            for position in matched.get(region, ()):
                self.addline(y, 4 + position, text[position], attr | self.match_attr)
        if query and not rows:
            self.addline(REGION_PICKER_TOP, 2, f"No regions match “{query}”.")
        if query is not None:
            try:
                self.screen.move(3, len(query) + 1)
            except curses.error:
                pass
        self.screen.refresh()
        return top

    def switch_region(self) -> None:
        if not self.select_region():
            return
        # The old region's rows would otherwise stay on screen, and selectable
        # with the new region's --region flag, until the fetch comes back.
        self.instances = []
        self.selected = 0
        self.top = 0
        self.start_reload()

    @property
    def shown(self) -> list[Instance]:
        """The instances on screen, which `selected` indexes.

        All of them, or with a search, those whose Name matches it, best
        match first.  Refiltered only when the list or the search changes.
        """
        cached = self.filtered_from
        if cached is None or cached[0] is not self.instances or cached[1] != self.query:
            self.filter_instances()
        return self.filtered

    def filter_instances(self) -> None:
        self.filtered_from = (self.instances, self.query)
        if not self.query:
            self.filtered = self.instances
            self.match_positions = {}
        else:
            matches = []
            for instance in self.instances:
                match = fuzzy_match(self.query, instance.name)
                if match:
                    matches.append((match[0], instance, match[1]))
            # Stable, so equally good matches keep their alphabetical order
            # after the shorter, closer names.
            matches.sort(key=lambda match: (-match[0], len(match[1].name)))
            self.filtered = [instance for _, instance, _ in matches]
            self.match_positions = {instance.instance_id: positions for _, instance, positions in matches}

    def set_query(self, query: str) -> None:
        self.query = query
        self.selected = 0  # the best match
        self.top = 0

    def start_search(self) -> None:
        self.searching = True
        self.set_cursor(1)

    def end_search(self, clear: bool = False) -> None:
        self.searching = False
        self.set_cursor(0)
        if clear:
            self.set_query("")

    def handle_search_key(self, key: int) -> None:
        """Edit the search while it has focus; the list narrows with every keystroke.

        Enter keeps the filter and opens the action menu on the selected
        match, so "/", a few letters and Enter reach an instance.  Esc drops
        the filter, and Backspace on an empty search just leaves it.
        """
        if key == 27:
            self.end_search(clear=True)
        elif key in (curses.KEY_ENTER, 10, 13):
            self.end_search()
            self.act_on_selected()
        elif key in (curses.KEY_BACKSPACE, curses.KEY_DC, 127, 8):
            if self.query:
                self.set_query(self.query[:-1])
            else:
                self.end_search()
        elif key == 21:  # Ctrl+U, as in a shell
            self.set_query("")
        elif key == curses.KEY_UP and self.shown:
            self.selected = max(0, self.selected - 1)
        elif key == curses.KEY_DOWN and self.shown:
            self.selected = min(len(self.shown) - 1, self.selected + 1)
        elif 32 <= key < 127:
            self.set_query(self.query + chr(key))

    def read_key(self, restore_timeout_ms: int | None = None) -> int:
        """Read a key, telling a real Esc apart from an unparsed escape sequence.

        curses hands back a bare 27 when the rest of an arrow-key sequence has
        not arrived yet, so binding Esc to quit made every arrow press risk
        popping the confirmation dialog.  A following byte means the 27 began a
        sequence; swallow the remainder instead of acting on it.
        """
        if restore_timeout_ms is None:
            restore_timeout_ms = self.poll_interval()
        key = self.screen.getch()
        if key != 27:
            return key
        self.screen.timeout(0)  # non-blocking peek at the rest of the sequence
        try:
            if self.screen.getch() == -1:
                return 27  # a genuine, standalone Esc
            for _ in range(16):  # escape sequences are short; never spin here
                if self.screen.getch() == -1:
                    break
            return -1
        finally:
            self.screen.timeout(restore_timeout_ms)

    def scroll_to_selection(self, visible: int) -> int:
        """Keep the selected row on screen, scrolling only when it leaves.

        Deriving the offset from the selection alone pinned the cursor to the
        last visible row and scrolled the whole list on every keypress.
        """
        if self.selected < self.top:
            self.top = self.selected
        elif self.selected >= self.top + visible:
            self.top = self.selected - visible + 1
        self.top = max(0, min(self.top, max(0, len(self.shown) - visible)))
        return self.top

    def draw(self, overlay: Callable[[], None] | None = None) -> None:
        """Redraw the screen, with `overlay` (a dialog) painted on top before the refresh."""
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        output_height = min(8, max(4, height // 3))
        output_top = height - output_height
        # Both boxes span columns 0..width-2 (addline never writes the last
        # column) and inset their contents two columns, inside the border.
        right = width - 2
        span = max(0, right - 1)
        inner = max(0, right - 3)

        self.draw_header(width)
        # A grey frame round the list.  Its title and the message ride in its
        # top and bottom edges, so they cost no list rows.
        frame_top = HEADER_ROWS
        self.addline(frame_top, 0, "┌" + "─" * span + "┐", self.rule_attr)
        for row in range(frame_top + 1, output_top - 1):
            self.addline(row, 0, "│", self.rule_attr)
            self.addline(row, right, "│", self.rule_attr)
        self.addline(output_top - 1, 0, "└" + "─" * span + "┘", self.rule_attr)
        caret = self.draw_frame_title(frame_top, span)
        if status := self.status_line():
            self.addline(output_top - 1, 1, f" {status} "[:inner + 1], curses.A_DIM)
        self.addline(frame_top + 1, 2, f"{'NAME':<{NAME_WIDTH}} {'INSTANCE ID':<{INSTANCE_ID_WIDTH}} {'STATE':<10} {'SSM STATUS':<14} {'TYPE':<11} {'PLATFORM':<8} PRIVATE IP"[:inner], curses.A_UNDERLINE)

        visible = max(1, output_top - LIST_TOP - 1)
        start = self.scroll_to_selection(visible)
        for row, instance in enumerate(self.shown[start : start + visible], start=LIST_TOP):
            attr = curses.A_REVERSE if start + row - LIST_TOP == self.selected else curses.A_NORMAL
            if instance.state == "stopped":
                attr |= curses.A_DIM
            if instance.ssm_status == NOT_MANAGED:
                attr |= self.unmanaged_attr
            self.addline(row, 2, instance.label[:inner], attr)
            for position in self.match_positions.get(instance.instance_id, ()):
                if position < min(NAME_WIDTH, inner):
                    self.addline(row, 2 + position, instance.name[position], attr | self.match_attr)
        if self.loading and not self.instances:
            self.draw_radar(visible, width)
        elif not self.instances:
            self.addline(LIST_TOP, 2, "No non-terminated EC2 instances found."[:inner])
        elif not self.shown:
            self.addline(LIST_TOP, 2, f"No instance names match “{self.query}”."[:inner])
        active = self.active_forwards()
        if any(forward.connected for forward in active):
            status_attr = self.active_status_attr
        elif active:
            status_attr = self.connecting_status_attr
        else:
            status_attr = self.disconnected_status_attr
        self.addline(output_top, 0, "┌" + f" {self.forward_status()} ".center(span, "─") + "┐", status_attr)
        for row in range(output_top + 1, height - 1):
            self.addline(row, 0, "│", status_attr)
            self.addline(row, right, "│", status_attr)
        self.addline(height - 1, 0, "└" + "─" * span + "┘", status_attr)
        panel_lines = output_height - 2
        for row, line in enumerate(list(self.output)[-panel_lines:], start=output_top + 1):
            self.addline(row, 2, line[:inner], curses.A_DIM)
        if overlay:
            overlay()
        elif self.searching:
            try:
                self.screen.move(frame_top, min(caret, max(0, right - 1)))
            except curses.error:
                pass
        self.screen.refresh()

    def draw_header(self, width: int) -> None:
        """Paint the k9s-style header: context on the left, key bindings on the right."""
        context = (
            ("Account", self.account.label if self.account else "…"),
            ("Profile", self.profile or "(default)"),
            ("Region", self.region or "(default)"),
            ("Identity", self.account.identity if self.account else "…"),
        )
        label_width = max(len(label) for label, _ in context) + 2
        value_width = max(len(value) for _, value in context)

        # Key bindings sit flush right, ending inside the frame's right edge.
        # They win the space over long context values, which are shortened
        # first; only then are whole columns dropped, never half a hint.
        keys = SEARCH_KEYS if self.searching else MAIN_KEYS + ((("Esc", "Clear search"),) if self.query else ())
        columns = []
        total = -3
        for start in range(0, len(keys), HEADER_ROWS):
            cells = keys[start : start + HEADER_ROWS]
            key_width = max(len(key) for key, _ in cells) + 2
            column_width = key_width + 1 + max(len(action) for _, action in cells)
            room = width - 2 - (total + 3 + column_width) - 4 - 1 - label_width
            if room < min(value_width, MIN_CONTEXT_WIDTH):
                break
            columns.append((cells, key_width, column_width))
            total += column_width + 3
        x = width - 2 - total
        for cells, key_width, column_width in columns:
            for row, (key, action) in enumerate(cells):
                self.addline(row, x, f"<{key}>", curses.A_BOLD)
                self.addline(row, x + key_width + 1, action, curses.A_DIM)
            x += column_width + 3

        room = max(1, width - 2 - (total + 4 if columns else 0) - 1 - label_width)
        for row, (label, value) in enumerate(context):
            if len(value) > room:
                value = value[: room - 1] + "…"
            self.addline(row, 1, f"{label}:", self.rule_attr)
            self.addline(row, 1 + label_width, value, curses.A_BOLD)

    def draw_frame_title(self, row: int, span: int) -> int:
        """While searching, centre ` </query> [shown/total] ` in the frame's top edge.

        Returns the column of the closing ">", where the search caret goes.
        """
        if not (self.searching or self.query):
            return 0
        query = f" </{self.query}> "
        count = f"[{len(self.shown)}/{len(self.instances)}] "
        x = 1 + max(0, (span - len(query) - len(count)) // 2)
        self.addline(row, x, query, curses.A_BOLD | self.match_attr)
        self.addline(row, x + len(query), count, curses.A_BOLD)
        return x + len(query) - 2

    def title(self) -> str:
        """The top line: which account, profile and region every action goes to."""
        parts = (
            f"account: {self.account.label}" if self.account else "",
            f"profile: {self.profile}" if self.profile else "",
            f"region: {self.region}" if self.region else "",
        )
        context = "  ".join(part for part in parts if part)
        return " ssmer " + (" — " + context if context else "")

    def draw_radar(self, visible: int, width: int) -> None:
        """Sweep a radar across the empty list area while instances load.

        A refresh keeps showing the current list instead; this only fills
        the screen when there is nothing else to look at.
        """
        elapsed = time.monotonic() - self.load_started
        caption = f"Scanning {self.region or 'the default region'} for EC2 instances · {elapsed:.1f}s"
        rows = min(RADAR_MAX_ROWS, visible - 2, (width - 6) // 2)  # clear of the frame
        if rows < RADAR_MIN_ROWS:
            self.addline(LIST_TOP, max(0, (width - len(caption)) // 2), caption, self.radar_attrs[2])
            return
        top = LIST_TOP + (visible - rows - 2) // 2
        left = (width - rows * 2) // 2
        angle = -math.pi / 2 + 2 * math.pi * elapsed / RADAR_REVOLUTION_S  # starts at twelve o'clock
        frame = radar_frame(rows * 2, rows, angle, radar_blips(self.region or ""))
        for y, (text, levels) in enumerate(frame, start=top):
            x = 0
            for level, run in itertools.groupby(levels):
                length = len(list(run))
                if level >= 0:
                    self.addline(y, left + x, text[x : x + length], self.radar_attrs[level])
                x += length
        self.addline(top + rows + 1, max(0, (width - len(caption)) // 2), caption, self.radar_attrs[2])

    def draw_dialog(self, lines: Sequence[str], highlight: int | None = None) -> tuple[int, int]:
        """Paint a centred reverse-video box; line `highlight` becomes a selection bar.

        Returns the screen position of the first line's text, for placing a caret.
        """
        height, width = self.screen.getmaxyx()
        box_width = min(width - 2, max(len(line) for line in lines) + 4)
        top = max(0, (height - len(lines) - 2) // 2)
        left = max(0, (width - box_width) // 2)

        for row in range(len(lines) + 2):
            self.addline(top + row, left, " " * box_width, curses.A_REVERSE)
        for row, line in enumerate(lines, start=1):
            if row - 1 == highlight:
                self.addline(top + row, left + 1, f" {line}".ljust(box_width - 2), curses.A_BOLD)
            else:
                self.addline(top + row, left + 2, line, curses.A_REVERSE)
        return top + 1, left + 2

    def draw_action_menu(self, target: Instance, selected: int) -> None:
        title = f"{target.name} ({target.instance_id})" if target.name else target.instance_id
        options = [f"[{hotkey}] {label:<13} {description}" for _, hotkey, label, description in ACTIONS]
        self.draw_dialog([title, "", *options, "", "↑/↓ choose · Enter select · Esc cancel"], highlight=2 + selected)

    def status_line(self) -> str:
        """The message line, with a spinner frame while a load is running."""
        if not self.loading:
            return self.message
        return f"{LOADING_FRAMES[self.spinner_frame % len(LOADING_FRAMES)]} {self.message}"

    def active_forwards(self) -> list[Forward]:
        return [forward for forward in self.forwards.values() if forward.process.poll() is None]

    def forward_status(self) -> str:
        """Return a concise, live summary for the header area."""
        active = self.active_forwards()
        if not active:
            return "STATUS: No active port forwards"
        now = time.monotonic()
        connecting = sum(not forward.connected for forward in active)
        counts = ", ".join(
            f"{count} {state}" for count, state in ((len(active) - connecting, "connected"), (connecting, "connecting")) if count
        )
        details = ", ".join(
            forward.route if forward.connected else f"{forward.route} (connecting {now - forward.started:.0f}s)"
            for forward in active
        )
        return f"STATUS: {counts} — {details}"

    def set_cursor(self, visible: int) -> None:
        """Show or hide the caret, tolerating terminals that cannot do either."""
        try:
            curses.curs_set(visible)
        except curses.error:
            pass

    def choose_ports(self, target: Instance) -> tuple[str, str] | None:
        """Ask for the remote and local ports in a dialog, returning None when it is cancelled.

        Both fields start at the defaults, and the first digit typed into a
        field replaces its value rather than adding to it, so another port is
        simply typed over the default.  Enter moves to the next field and, from
        the last, starts the forward.  A problem with the ports is shown in the
        dialog, which stays open so it can be fixed.

        The line editing is done by hand because curses' getstr() cannot be
        cancelled: it echoes Esc as a literal "^[" and goes on waiting for
        Enter.  The main event loop polls every 200 ms, so the dialog must
        also block on input rather than time out.
        """
        values = [DEFAULT_REMOTE_PORT, DEFAULT_LOCAL_PORT]
        edited = [False, False]
        field = 0
        error = ""
        self.screen.timeout(-1)
        self.set_cursor(1)
        try:
            while True:
                self.draw(lambda: self.draw_port_dialog(target, values, field, error))
                key = self.read_key(-1)
                if key == 27:
                    return None
                if key in (9, curses.KEY_BTAB):  # Tab and Shift+Tab: two fields, so either way toggles
                    field = 1 - field
                elif key == curses.KEY_UP:
                    field = 0
                elif key == curses.KEY_DOWN:
                    field = 1
                elif key in (curses.KEY_ENTER, 10, 13):
                    if field == 0:
                        field = 1
                        continue
                    problem = self.port_problem(*values)
                    if problem is None:
                        return str(int(values[0])), str(int(values[1]))
                    field, error = problem
                elif key in (curses.KEY_BACKSPACE, curses.KEY_DC, 127, 8):
                    values[field] = values[field][:-1]
                    edited[field] = True
                    error = ""
                elif ord("0") <= key <= ord("9"):
                    if not edited[field]:
                        values[field] = ""
                        edited[field] = True
                    if len(values[field]) < PORT_DIGITS:
                        values[field] += chr(key)
                    error = ""
                # Anything else — a letter, a resize, a swallowed escape
                # sequence — just redraws on the next pass.
        except KeyboardInterrupt:
            return None
        finally:
            self.set_cursor(0)
            self.screen.timeout(self.poll_interval())

    def port_problem(self, remote: str, local: str) -> tuple[int, str] | None:
        """What stops a forward on these ports, as (the field to fix, why), or None."""
        if not valid_port(remote):
            return 0, "The remote port must be from 1 through 65535."
        if not valid_port(local):
            return 1, "The local port must be from 1 through 65535."
        local = str(int(local))
        if local in self.forwards and self.forwards[local].process.poll() is None:
            return 1, f"localhost:{local} is already forwarded; disconnect it or choose another port."
        if local_port_in_use(int(local)):
            # The plugin cannot open a port that is taken, and may hang rather
            # than say so.  A tunnel left running by an earlier ssmer is the
            # usual culprit, since quitting leaves forwards up by default.
            return 1, f"localhost:{local} is in use by another program (a tunnel from an earlier ssmer?)."
        return None

    def draw_port_dialog(self, target: Instance, values: Sequence[str], field: int, error: str) -> None:
        name = f"{target.name} ({target.instance_id})" if target.name else target.instance_id
        fields = [f"{label:<13}{value}" for label, value in zip(("Remote port", "Local port"), values, strict=True)]
        lines = [f"Port forward to {name}", "", *fields, ""]
        if error:
            lines += [error, ""]
        lines.append("Tab/↑/↓ switch · Enter next/start · Esc cancel")
        top, left = self.draw_dialog(lines, highlight=2 + field)
        try:
            self.screen.move(top + 2 + field, left + len(fields[field]))
        except curses.error:
            pass

    def act_on_selected(self) -> None:
        """Offer Connect or Port Forward for the selected instance, then run the choice."""
        if not self.shown:
            return
        target = self.shown[self.selected]
        if target.state != "running":
            self.message = f"{target.instance_id} is {target.state}; start it before creating a session."
            return
        action = self.choose_action(target)
        if action == CONNECT:
            self.start_shell(target)
        elif action == PORT_FORWARD and self.start_forward(target):
            self.offer_admin_password(target)

    def choose_action(self, target: Instance) -> str | None:
        """Show the action menu for `target`, returning None when it is cancelled."""
        hotkeys = {ord(hotkey): action for action, hotkey, _, _ in ACTIONS}
        selected = 0
        self.screen.timeout(-1)
        try:
            while True:
                self.draw(lambda: self.draw_action_menu(target, selected))
                key = self.read_key(-1)
                if key in (27, ord("q")):
                    return None
                if key in hotkeys:
                    return hotkeys[key]
                if key in (curses.KEY_UP, ord("k")):
                    selected = max(0, selected - 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    selected = min(len(ACTIONS) - 1, selected + 1)
                elif key in (curses.KEY_ENTER, 10, 13):
                    return ACTIONS[selected][0]
        except KeyboardInterrupt:
            return None
        finally:
            self.screen.timeout(self.poll_interval())

    @contextlib.contextmanager
    def suspended(self):
        """Give the terminal back to ordinary line-by-line use for the block."""
        curses.def_prog_mode()
        curses.endwin()
        try:
            yield
        finally:
            curses.reset_prog_mode()
            curses.flushinp()  # keys typed into the session must not drive the list
            self.screen.clear()  # repaint everything the session scrolled over

    def start_shell(self, target: Instance) -> None:
        """Open an interactive Session Manager shell in this terminal.

        The session needs the real terminal, so the TUI is suspended until the
        remote shell exits.  Port forwards keep running in the background.
        """
        name = target.name or target.instance_id
        command = aws_command(self.profile, self.region, "ssm", "start-session", "--target", target.instance_id)
        self.log("$ " + " ".join(command))
        with self.suspended():
            print(f"Connecting to {name} ({target.instance_id}). Type 'exit' to return to ssmer.", flush=True)
            try:
                status = run_interactive(command)
            except OSError as error:
                self.message = f"Could not start AWS CLI: {error}"
                return
            if status:
                # Without a pause the error the AWS CLI just printed would be
                # painted over the moment the TUI comes back.
                wait_for_enter(f"\nSession exited with status {status}. Press Enter to return to ssmer…")
        self.log(f"Session with {target.instance_id} ended (exit status {status}).")
        if not status:
            self.message = f"Session with {name} closed."
            return
        caveat = "" if target.ssm_status == "Online" else f" (SSM status: {target.ssm_status})"
        self.message = f"Session with {name} failed (exit status {status}).{caveat}"

    def start_forward(self, target: Instance) -> bool:
        """Ask for the ports and start the tunnel, returning whether it started."""
        ports = self.choose_ports(target)
        if ports is None:
            self.message = "Forward cancelled."
            return False
        remote, local = ports
        command = aws_command(
            self.profile, self.region, "ssm", "start-session", "--target", target.instance_id,
            "--document-name", "AWS-StartPortForwardingSession",
            "--parameters", f"portNumber={remote},localPortNumber={local}",
        )
        self.log("$ " + " ".join(command))
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError as error:
            self.message = f"Could not start AWS CLI: {error}"
            return False
        forward = Forward(target, remote, local, process)
        self.forwards[local] = forward
        if process.stdout:
            forward.watcher = threading.Thread(target=self.watch_output, args=(process.stdout, forward), daemon=True)
            forward.watcher.start()
        # The SSM ping status is a strong predictor of failure, but it can be
        # stale or absent, so flag it rather than refusing to try.
        caveat = "" if target.ssm_status == "Online" else f" (SSM status: {target.ssm_status})"
        self.message = f"Connecting to {target.name or target.instance_id}: localhost:{local} → {remote}…{caveat}"
        return True

    def offer_admin_password(self, target: Instance) -> None:
        """Let the user pick a key file, then fetch the Administrator password in the background.

        A missing or empty keys directory is reported but does not stop the
        forward, which is already on its way up.
        """
        keys = find_key_files(self.keys_dir)
        if not keys:
            error = f"No EC2 key files in {self.keys_dir}; cannot fetch the Administrator password."
            self.log(f"Error: {error}")
            self.message = f"{self.message} {error}"
            return
        launch_key = next((key for key in keys if target.key_name and key.stem == target.key_name), None)
        key_file = self.choose_key(target, self.keys_dir, launch_key)
        if key_file is None:
            return
        name = target.name or target.instance_id
        self.log(f"Fetching the Administrator password for {name} with {key_file.name}…")
        threading.Thread(
            target=self.fetch_admin_password, args=(target, key_file, self.profile, self.region), daemon=True
        ).start()

    def fetch_admin_password(self, target: Instance, key_file: Path, profile: str | None, region: str | None) -> None:
        """Worker body: decrypt the password, copy it, and report back through the queues."""
        name = target.name or target.instance_id
        try:
            password = get_admin_password(profile, region, target.instance_id, key_file)
        except (RuntimeError, OSError, json.JSONDecodeError) as error:
            self.output_queue.put(f"Error: could not fetch the Administrator password for {name}: {error}")
            self.message_queue.put(f"Could not fetch the Administrator password for {name}: {error}")
            return
        tool = copy_to_clipboard(password)
        if tool:
            self.output_queue.put(f"Administrator password for {name} copied to the clipboard ({tool}).")
            self.message_queue.put(f"Administrator password for {name} copied to the clipboard.")
        else:
            # Kept out of the output panel, which stays on screen.
            self.output_queue.put(f"No clipboard tool available; the Administrator password for {name} is on the status line.")
            self.message_queue.put(f"Administrator password for {name}: {password}")

    def choose_key(self, target: Instance, root: Path, launch_key: Path | None = None) -> Path | None:
        """Browse `root` for a key file, returning the chosen file or None when it is skipped.

        Enter opens a directory or picks a file, and ←/Backspace goes back up,
        but never above `root`.  When a file is named after the instance's key
        pair, the browser opens in its directory with that file highlighted.
        """
        directory = launch_key.parent if launch_key else root
        highlight = launch_key
        self.screen.timeout(-1)
        try:
            while True:
                subdirectories, files = list_key_directory(directory)
                entries = ([directory.parent] if directory != root else []) + subdirectories + files
                selected = entries.index(highlight) if highlight in entries else 0
                page = self.key_picker_rows()
                while True:
                    self.draw(lambda: self.draw_key_picker(target, root, directory, entries, selected))
                    key = self.read_key(-1)
                    if key in (27, ord("q")):
                        return None
                    if key in (curses.KEY_UP, ord("k")):
                        selected = max(0, selected - 1)
                    elif key in (curses.KEY_DOWN, ord("j")):
                        selected = min(len(entries) - 1, selected + 1)
                    elif key == curses.KEY_PPAGE:
                        selected = max(0, selected - page)
                    elif key == curses.KEY_NPAGE:
                        selected = min(len(entries) - 1, selected + page)
                    elif key in (curses.KEY_LEFT, curses.KEY_BACKSPACE, 127, 8, ord("h")) and directory != root:
                        highlight, directory = directory, directory.parent
                        break
                    elif key in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT, ord("l")) and entries:
                        chosen = entries[selected]
                        if chosen in files:
                            if key in (curses.KEY_RIGHT, ord("l")):
                                continue  # only Enter picks a file
                            return chosen
                        # Going up highlights the directory just left.
                        highlight = directory if chosen == directory.parent and directory != root else None
                        directory = chosen
                        break
        except KeyboardInterrupt:
            return None
        finally:
            self.screen.timeout(self.poll_interval())

    def key_picker_rows(self) -> int:
        """How many entries the key browser shows at once, leaving room for its frame."""
        height, _ = self.screen.getmaxyx()
        return max(1, min(KEY_PICKER_ROWS, height - 9))

    def draw_key_picker(
        self, target: Instance, root: Path, directory: Path, entries: Sequence[Path], selected: int
    ) -> None:
        rows = self.key_picker_rows()
        start = max(0, min(selected - rows // 2, len(entries) - rows))
        up = directory.parent if directory != root else None
        shown = []
        for entry in entries[start : start + rows]:
            if entry == up:
                shown.append("../")
            elif entry.is_dir():
                shown.append(f"{entry.name}/")
            else:
                shown.append(entry.name + ("  (launch key)" if target.key_name and entry.stem == target.key_name else ""))
        if len(entries) == (1 if up else 0):
            shown.append("(empty)")
        location = root.name if directory == root else f"{root.name}/{directory.relative_to(root)}"
        position = f"  [{selected + 1}/{len(entries)}]" if len(entries) > rows else ""
        title = f"Key for the Administrator password of {target.name or target.instance_id}"
        footer = "↑/↓ move · Enter open/fetch · ←/Backspace up · Esc skip"
        self.draw_dialog(
            [title, f"{location}/{position}", "", *shown, "", footer],
            highlight=3 + selected - start if entries else None,
        )

    def stop_forward(self, forward: Forward) -> None:
        forward.exit_reported = True
        try:
            os.killpg(forward.process.pid, signal.SIGTERM)
        except OSError as error:
            self.log(f"Could not stop {forward.route}: {error}")
        else:
            self.log(f"Disconnected {forward.route}.")

    def disconnect_selected(self) -> None:
        if not self.shown:
            return
        target = self.shown[self.selected]
        matching = [forward for forward in self.active_forwards() if forward.instance.instance_id == target.instance_id]
        if not matching:
            self.message = f"No active forwards for {target.name or target.instance_id}."
            return
        for forward in matching:
            self.stop_forward(forward)
        self.message = f"Disconnect requested for {len(matching)} forward(s) on {target.name or target.instance_id}."

    def disconnect_all(self) -> int:
        """Stop every forward, including ones whose instance is no longer listed.

        Switching regions or refreshing can leave a live tunnel with no row to
        select, so `d` alone cannot always reach it.
        """
        active = self.active_forwards()
        if not active:
            self.message = "No active port forwards to disconnect."
            return 0
        for forward in active:
            self.stop_forward(forward)
        self.message = f"Disconnect requested for all {len(active)} forward(s)."
        return len(active)

    def confirm_quit(self) -> bool:
        """Show a modal quit prompt with buttons and return whether to quit.

        ←/→ (or h/l, Tab) move between the buttons and Enter presses one; the
        y, d and n shortcuts still act straight away.
        """
        active = bool(self.active_forwards())
        detail = "Active port forwards will keep running." if active else "No port forwards are active."
        buttons = ("quit", "disconnect", "cancel") if active else ("quit", "cancel")
        shortcuts = {ord("y"): "quit", ord("Y"): "quit", ord("n"): "cancel", ord("N"): "cancel", 27: "cancel"}
        if active:
            shortcuts.update({ord("d"): "disconnect", ord("D"): "disconnect"})
        selected = 0
        self.screen.timeout(-1)
        try:
            while True:
                self.draw(lambda: self.draw_quit_dialog(detail, buttons, selected))
                key = self.read_key(-1)
                if key in shortcuts:
                    choice = shortcuts[key]
                elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                    choice = buttons[selected]
                else:
                    if key in (curses.KEY_LEFT, ord("h"), curses.KEY_BTAB):
                        selected = (selected - 1) % len(buttons)
                    elif key in (curses.KEY_RIGHT, ord("l"), 9):
                        selected = (selected + 1) % len(buttons)
                    continue
                if choice == "disconnect":
                    self.disconnect_all()
                return choice != "cancel"
        except KeyboardInterrupt:
            return False
        finally:
            self.screen.timeout(POLL_INTERVAL_MS)

    def draw_quit_dialog(self, detail: str, buttons: Sequence[str], selected: int) -> None:
        """The quit prompt: its buttons sit on one row, the focused one lit."""
        labels = [f"[ {QUIT_BUTTONS[button]} ]" for button in buttons]
        row_text = "  ".join(labels)
        top, left = self.draw_dialog((" Quit ssmer? ", detail, "", row_text, "", "←/→ choose · Enter select · Esc cancel"))
        x = left
        for index, label in enumerate(labels):
            self.addline(top + 3, x, label, curses.A_BOLD if index == selected else curses.A_REVERSE)
            x += len(label) + 2

    def run(self) -> None:
        self.set_cursor(0)
        self.screen.keypad(True)
        self.screen.timeout(POLL_INTERVAL_MS)
        try:
            # Without this ncurses waits a full second before deciding a lone
            # Esc is not the start of a longer key sequence.
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass
        self.configure_colors()
        self.check_dependencies()
        if not self.check_session() or not self.select_region():
            return
        self.start_reload()
        while True:
            self.screen.timeout(self.poll_interval())
            self.drain_output()
            self.drain_load_results()
            self.update_forwards()
            self.draw()
            if self.loading:
                self.spinner_frame += 1
            key = self.read_key()
            if key == -1:
                continue
            if self.searching:
                self.handle_search_key(key)
            elif key == 27 and self.query:
                self.set_query("")  # Esc drops a filter before it quits
            elif key in (ord("q"), 27):
                if self.confirm_quit():
                    return
            elif key == ord("/"):
                self.start_search()
            elif key in (curses.KEY_UP, ord("k")) and self.shown:
                self.selected = max(0, self.selected - 1)
            elif key in (curses.KEY_DOWN, ord("j")) and self.shown:
                self.selected = min(len(self.shown) - 1, self.selected + 1)
            elif key == ord("r"):
                self.start_reload()
            elif key == ord("g"):
                self.switch_region()
            elif key == ord("d"):
                self.disconnect_selected()
            elif key == ord("D"):
                self.disconnect_all()
            elif key in (curses.KEY_ENTER, 10, 13):
                self.act_on_selected()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ssmer: TUI for EC2 shell sessions and port forwarding via AWS Systems Manager.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--region", help="AWS region to use")
    parser.add_argument(
        "--keys-dir", type=Path,
        default=Path(os.environ["SSMER_KEYS_DIR"]) if os.environ.get("SSMER_KEYS_DIR") else DEFAULT_KEYS_DIR,
        help=f"directory of EC2 key files for Windows Administrator passwords (default: $SSMER_KEYS_DIR or {DEFAULT_KEYS_DIR})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        curses.wrapper(lambda screen: App(screen, args.profile, args.region, args.keys_dir).run())
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
