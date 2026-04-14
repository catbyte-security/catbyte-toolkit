"""Tests for the plugin system."""
import os
import sys
import textwrap

import pytest

from cb.cli import _register_plugins, _get_plugin_dir


@pytest.fixture
def plugin_dir(tmp_path):
    """Create a temporary plugin directory."""
    d = tmp_path / "plugins"
    d.mkdir()
    return d


@pytest.fixture
def _patch_plugin_dir(monkeypatch, plugin_dir):
    """Patch _get_plugin_dir to return our temp dir."""
    monkeypatch.setattr("cb.cli._get_plugin_dir", lambda: str(plugin_dir))


class TestPluginDiscovery:
    def test_empty_dir_no_crash(self, _patch_plugin_dir, plugin_dir):
        """An empty plugin directory should not crash."""
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)  # should not raise

    def test_nonexistent_dir_no_crash(self, monkeypatch):
        """A nonexistent plugin directory should not crash."""
        monkeypatch.setattr("cb.cli._get_plugin_dir",
                            lambda: "/nonexistent/path/plugins")
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)  # should not raise

    def test_valid_plugin_registers_command(self, _patch_plugin_dir, plugin_dir):
        """A valid plugin with register() should add its command."""
        plugin_code = textwrap.dedent("""\
            def register(subparsers):
                p = subparsers.add_parser("hello-plugin", help="A test plugin")
                p.set_defaults(func=lambda args: None)
        """)
        (plugin_dir / "hello.py").write_text(plugin_code)

        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)

        # The command should be parseable
        args = parser.parse_args(["hello-plugin"])
        assert args.command == "hello-plugin"

    def test_broken_plugin_no_crash(self, _patch_plugin_dir, plugin_dir, capsys):
        """A plugin with a syntax error should emit a warning, not crash."""
        (plugin_dir / "broken.py").write_text("def register(subparsers):\n    +++bad")

        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)  # should not raise

        captured = capsys.readouterr()
        assert "broken.py" in captured.err

    def test_underscore_files_skipped(self, _patch_plugin_dir, plugin_dir):
        """Files starting with _ should be skipped."""
        plugin_code = textwrap.dedent("""\
            def register(subparsers):
                subparsers.add_parser("should-not-appear")
        """)
        (plugin_dir / "_helper.py").write_text(plugin_code)

        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)

        # The command should NOT be registered
        with pytest.raises(SystemExit):
            parser.parse_args(["should-not-appear"])

    def test_plugin_without_register_skipped(self, _patch_plugin_dir, plugin_dir, capsys):
        """A plugin file without register() should be skipped with a warning."""
        (plugin_dir / "no_register.py").write_text("x = 42\n")

        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)

        captured = capsys.readouterr()
        assert "no_register.py" in captured.err
        assert "no register()" in captured.err

    def test_plugins_load_in_sorted_order(self, _patch_plugin_dir, plugin_dir):
        """Plugins should be loaded in alphabetical order."""
        load_order = []
        for name in ["zzz", "aaa", "mmm"]:
            code = textwrap.dedent(f"""\
                def register(subparsers):
                    import tests.test_plugins as tp
                    if hasattr(tp, '_load_order'):
                        tp._load_order.append("{name}")
                    subparsers.add_parser("plug-{name}")
            """)
            (plugin_dir / f"{name}.py").write_text(code)

        import tests.test_plugins as tp
        tp._load_order = load_order

        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        _register_plugins(sub)

        assert load_order == ["aaa", "mmm", "zzz"]
        del tp._load_order


class TestGetPluginDir:
    def test_default_from_config(self):
        """_get_plugin_dir should return the config value."""
        d = _get_plugin_dir()
        assert isinstance(d, str)
        assert "plugins" in d
