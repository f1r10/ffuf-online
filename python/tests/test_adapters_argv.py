"""Adapter argv tests.

Hard rules verified here: ``build_arguments`` returns a ``list[str]`` (never a
shell string), forbidden shell metacharacters are rejected, and unknown /
missing inputs are refused.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

from adapters.arjun import ArjunAdapter
from adapters.base import AdapterInputError
from adapters.dnsx import DnsxAdapter
from adapters.feroxbuster import FeroxbusterAdapter
from adapters.ffuf import FfufAdapter
from adapters.gau import GauAdapter
from adapters.httpx import HttpxAdapter
from adapters.katana import KatanaAdapter
from adapters.kiterunner import KiterunnerAdapter
from adapters.nmap import NmapAdapter
from adapters.nuclei import NucleiAdapter
from adapters.registry import default_registry
from adapters.runner import DockerRunner, LocalProcessRunner, RunnerError
from adapters.subfinder import SubfinderAdapter
from ffuf_intel.config import Config

METACHARS = set(";|`$><\n\r")

PY_DIR = pathlib.Path(__file__).resolve().parents[1]
BINDIR = PY_DIR / "tools" / "bin"


def _task(input_data):
    return {"tenant_id": "t1", "project_id": "p1", "id": "task-1", "input": input_data}


EXTRA_CASES = [
    (SubfinderAdapter, {"domain": "example.com"}, ["-d", "example.com", "-silent", "-json", "-oJ"]),
    (DnsxAdapter, {"hostname": "api.example.com"}, ["-silent", "-json", "-a", "-aaaa", "-cname", "-d", "api.example.com"]),
    (HttpxAdapter, {"hostname": "api.example.com"}, ["-json", "-silent", "-u", "api.example.com"]),
    (KatanaAdapter, {"http_service": "https://api.example.com"}, ["-json", "-silent", "-u", "https://api.example.com", "-jc"]),
    (GauAdapter, {"domain": "example.com"}, ["--threads", "2", "example.com"]),
    (
        FfufAdapter,
        {"url": "https://example.com"},
        ["-u", "https://example.com", "-w", "/wordlists/default.txt", "-mc", "200,204,301,302,307,401,403,405", "-o", "/tmp/ffuf-report.json", "-of", "json"],
    ),
    (
        FeroxbusterAdapter,
        {"url": "https://example.com"},
        ["--json", "--silent", "--url", "https://example.com", "--wordlist", "/wordlists/default.txt"],
    ),
    (KiterunnerAdapter, {"api_host": "https://api.example.com"}, ["scan", "https://api.example.com", "-w", "/wordlists/default.txt", "-o", "json"]),
    (ArjunAdapter, {"endpoint": "https://api.example.com/api/v2/users"}, ["-u", "https://api.example.com/api/v2/users", "-j"]),
    (NucleiAdapter, {"url": "https://api.example.com"}, ["-jsonl", "-silent", "-t", "/templates/", "-u", "https://api.example.com"]),
    (NmapAdapter, {"hostname": "api.example.com"}, ["-oX", "-", "-Pn", "-sV", "-p", "80,443", "api.example.com"]),
]


@pytest.mark.parametrize("adapter_cls,input_data,expected", EXTRA_CASES)
def test_build_arguments_returns_argv_list(adapter_cls, input_data, expected):
    argv = adapter_cls().build_arguments(_task(input_data))
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)
    assert argv == expected


@pytest.mark.parametrize("adapter_cls,input_data,_expected", EXTRA_CASES)
def test_argv_never_contains_shell_metacharacters(adapter_cls, input_data, _expected):
    argv = adapter_cls().build_arguments(_task(input_data))
    for arg in argv:
        assert not (set(arg) & METACHARS), f"metacharacter leaked into argv: {arg!r}"


def test_registry_covers_all_eleven_adapters():
    registry = default_registry()
    assert registry.ids() == sorted(
        ["subfinder", "dnsx", "httpx", "katana", "gau", "ffuf", "feroxbuster", "kiterunner", "arjun", "nuclei", "nmap"]
    )


def test_unknown_input_keys_are_rejected():
    with pytest.raises(AdapterInputError):
        SubfinderAdapter().build_arguments(_task({"domain": "example.com", "evil": "x"}))


def test_missing_required_input_is_rejected():
    with pytest.raises(AdapterInputError):
        SubfinderAdapter().build_arguments(_task({}))


def test_shell_metacharacters_in_values_are_rejected():
    with pytest.raises(AdapterInputError):
        SubfinderAdapter().build_arguments(_task({"domain": "example.com; rm -rf /"}))
    with pytest.raises(AdapterInputError):
        HttpxAdapter().build_arguments(_task({"hostname": "api.example.com; whoami"}))
    with pytest.raises(AdapterInputError):
        HttpxAdapter().build_arguments(_task({"hostname": "api.example.com|id"}))


def test_whitespace_only_value_is_rejected():
    with pytest.raises(AdapterInputError):
        KatanaAdapter().build_arguments(_task({"http_service": "   "}))


def test_optional_flag_is_appended_only_when_present():
    with_severity = NucleiAdapter().build_arguments(
        _task({"url": "https://api.example.com", "severity": "low"})
    )
    assert with_severity[-2:] == ["-severity", "low"]
    without = NucleiAdapter().build_arguments(_task({"url": "https://api.example.com"}))
    assert "-severity" not in without


def test_docker_runner_builds_a_hardened_command():
    command = DockerRunner().build_command("nuclei", "projectdiscovery/nuclei:3.3.5", ["-u", "https://x"])
    assert command[0] == "docker"
    assert "--network" in command
    assert "--read-only" in command
    assert "--cap-drop" in command and "ALL" in command
    assert "no-new-privileges" in command
    assert command[-1] == "https://x"
    assert "projectdiscovery/nuclei:3.3.5" in command


def test_docker_runner_requires_an_image():
    with pytest.raises(RunnerError):
        DockerRunner().run("nuclei", ["-u", "https://x"])


def test_local_runner_resolves_stub_and_refuses_escape():
    runner = LocalProcessRunner(Config(), bindir=str(BINDIR))
    resolved = runner.resolve("subfinder")
    assert resolved[0] == sys.executable
    assert resolved[1].endswith("subfinder.py")
    with pytest.raises(AdapterInputError):
        runner.resolve("../evil")
    with pytest.raises(RunnerError):
        runner.resolve("does_not_exist")


def test_local_runner_executes_a_demo_standin_and_parses():
    from adapters.katana import KatanaAdapter

    runner = LocalProcessRunner(Config(), bindir=str(BINDIR))
    adapter = KatanaAdapter()
    result = adapter.execute(_task({"http_service": "https://api.example.com"}), runner)
    assert result.exit_code == 0
    parsed = result.artifacts["parsed"]
    assert parsed["endpoints"], "the katana demo stand-in should yield an endpoint"
