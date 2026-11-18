"""Tests for selecting an isolated CLI configuration directory."""

from linux_admin.main import build_parser


def test_cli_accepts_an_explicit_config_directory():
    args = build_parser().parse_args(
        ["--check-config", "--config-dir", "/tmp/linux-admin-v1-test-config"]
    )
    assert args.check_config is True
    assert args.config_dir == "/tmp/linux-admin-v1-test-config"


def test_cli_config_directory_is_optional():
    args = build_parser().parse_args(["--check-config"])
    assert args.config_dir is None
