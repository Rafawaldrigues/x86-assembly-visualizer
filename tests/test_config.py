"""Tests of the configuration: defaults, files, environment and validation."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

from asmx.config import CANDIDATE_NAMES, CONFIG_ENV_VAR, SandboxConfig
from asmx.errors import ConfigError
from asmx.logging_setup import reset_logging

#: YAML is optional: its tests only run when PyYAML is installed.
HAS_YAML = importlib.util.find_spec("yaml") is not None


class TestDefaults(unittest.TestCase):
    """The configuration with no argument at all needs to be sensible."""

    def test_defaults(self) -> None:
        config = SandboxConfig()
        self.assertEqual(config.timeout, 30.0)
        self.assertEqual(config.max_steps, 200000)
        self.assertEqual(config.max_memory, 512)
        self.assertFalse(config.enable_network)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.workers, 4)

    def test_to_dict_and_field_names(self) -> None:
        config = SandboxConfig()
        self.assertEqual(tuple(config.to_dict()), config.field_names())
        self.assertEqual(len(config.field_names()), 10)

    def test_describe_in_one_line(self) -> None:
        text = SandboxConfig(timeout=2, max_steps=10).describe()
        self.assertIn("timeout=2s", text)
        self.assertIn("max_steps=10", text)
        self.assertIn("network=off", text)

    def test_repr_uses_describe(self) -> None:
        self.assertTrue(repr(SandboxConfig()).startswith("SandboxConfig(timeout="))

    def test_type_conversion_at_construction(self) -> None:
        config = SandboxConfig(
            timeout="5", max_steps="1000", workers="2", log_json="yes", strict="0"
        )
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.max_steps, 1000)
        self.assertEqual(config.workers, 2)
        self.assertTrue(config.log_json)
        self.assertFalse(config.strict)

    def test_log_level_in_lowercase(self) -> None:
        self.assertEqual(SandboxConfig(log_level="debug").log_level, "DEBUG")


class TestValidation(unittest.TestCase):
    """Values out of range need to be refused with the field in the context."""

    def check_field(self, field: str, **values: object) -> ConfigError:
        with self.assertRaises(ConfigError) as context:
            SandboxConfig(**values).validate()
        self.assertEqual(context.exception.field, field)
        return context.exception

    def test_timeout_needs_to_be_positive(self) -> None:
        self.check_field("timeout", timeout=0)

    def test_absurd_timeout(self) -> None:
        self.check_field("timeout", timeout=100000)

    def test_minimum_max_steps(self) -> None:
        self.check_field("max_steps", max_steps=0)

    def test_minimum_memory(self) -> None:
        self.check_field("max_memory", max_memory=1)

    def test_unknown_level(self) -> None:
        self.check_field("log_level", log_level="NOISE")

    def test_workers_out_of_range(self) -> None:
        self.check_field("workers", workers=0)
        self.check_field("workers", workers=999)

    def test_empty_output_directory(self) -> None:
        self.check_field("output_dir", output_dir="   ")

    def test_validate_returns_the_config_itself(self) -> None:
        config = SandboxConfig()
        self.assertIs(config.validate(), config)

    def test_invalid_boolean_value(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig(strict="maybe")

    def test_invalid_number(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig(timeout="lots")


class TestFromDict(unittest.TestCase):
    """Reading a dictionary, with a suggestion for a wrong field."""

    def test_known_fields(self) -> None:
        config = SandboxConfig.from_dict({"workers": "2", "strict": True})
        self.assertEqual(config.workers, 2)
        self.assertTrue(config.strict)

    def test_empty_dict(self) -> None:
        self.assertEqual(SandboxConfig.from_dict(None).timeout, 30.0)

    def test_unknown_field_with_a_suggestion(self) -> None:
        with self.assertRaises(ConfigError) as context:
            SandboxConfig.from_dict({"timeoutt": 5})
        self.assertIn("timeout", str(context.exception))
        self.assertEqual(context.exception.field, "timeoutt")

    def test_unknown_field_without_a_similar_one(self) -> None:
        with self.assertRaises(ConfigError) as context:
            SandboxConfig.from_dict({"xyzzy": 1})
        self.assertNotIn("did you mean", str(context.exception))

    def test_origin_appears_in_the_message(self) -> None:
        with self.assertRaises(ConfigError) as context:
            SandboxConfig.from_dict({"nothing": 1}, path="asmx.json")
        self.assertIn("asmx.json", str(context.exception))

    def test_invalid_value_in_the_dict(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig.from_dict({"timeout": -1})


class TestMerged(unittest.TestCase):
    """Overriding fields."""

    def test_overrides(self) -> None:
        config = SandboxConfig().merged(timeout=3, workers=2)
        self.assertEqual(config.timeout, 3.0)
        self.assertEqual(config.workers, 2)

    def test_none_is_ignored(self) -> None:
        config = SandboxConfig(timeout=7).merged(timeout=None, workers=3)
        self.assertEqual(config.timeout, 7.0)
        self.assertEqual(config.workers, 3)

    def test_unknown_field(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig().merged(invented=1)

    def test_does_not_change_the_original(self) -> None:
        original = SandboxConfig()
        original.merged(timeout=1)
        self.assertEqual(original.timeout, 30.0)


class TestFiles(unittest.TestCase):
    """Reading and writing in JSON and YAML."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.json_path = os.path.join(self.dir.name, "config.json")
        with open(self.json_path, "w", encoding="utf-8") as file:
            json.dump({"timeout": 5, "workers": 2, "log_level": "warning"}, file)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_valid_json(self) -> None:
        config = SandboxConfig.from_json_file(self.json_path)
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.workers, 2)
        self.assertEqual(config.log_level, "WARNING")

    def test_missing_json(self) -> None:
        with self.assertRaises(ConfigError) as context:
            SandboxConfig.from_json_file(os.path.join(self.dir.name, "nothing.json"))
        self.assertEqual(context.exception.path, os.path.join(self.dir.name, "nothing.json"))

    def test_invalid_json(self) -> None:
        path = os.path.join(self.dir.name, "broken.json")
        with open(path, "w", encoding="utf-8") as file:
            file.write("{this is not json}")
        with self.assertRaises(ConfigError) as context:
            SandboxConfig.from_json_file(path)
        self.assertIn("invalid JSON", str(context.exception))

    def test_json_needs_to_be_an_object(self) -> None:
        path = os.path.join(self.dir.name, "list.json")
        with open(path, "w", encoding="utf-8") as file:
            json.dump([1, 2], file)
        with self.assertRaises(ConfigError):
            SandboxConfig.from_json_file(path)

    def test_from_file_by_extension(self) -> None:
        self.assertEqual(SandboxConfig.from_file(self.json_path).timeout, 5.0)

    def test_from_file_unknown_extension(self) -> None:
        with self.assertRaises(ConfigError) as context:
            SandboxConfig.from_file(os.path.join(self.dir.name, "config.ini"))
        self.assertIn("extension", str(context.exception))

    @unittest.skipUnless(HAS_YAML, "PyYAML is not installed")
    def test_valid_yaml(self) -> None:
        path = os.path.join(self.dir.name, "asmx.yaml")
        with open(path, "w", encoding="utf-8") as file:
            file.write("timeout: 9\nworkers: 3\n")
        config = SandboxConfig.from_yaml_file(path)
        self.assertEqual(config.timeout, 9.0)
        self.assertEqual(config.workers, 3)

    @unittest.skipUnless(HAS_YAML, "PyYAML is not installed")
    def test_empty_yaml_uses_the_defaults(self) -> None:
        path = os.path.join(self.dir.name, "empty.yaml")
        with open(path, "w", encoding="utf-8") as file:
            file.write("")
        self.assertEqual(SandboxConfig.from_yaml_file(path).timeout, 30.0)

    @unittest.skipUnless(HAS_YAML, "PyYAML is not installed")
    def test_invalid_yaml(self) -> None:
        path = os.path.join(self.dir.name, "bad.yaml")
        with open(path, "w", encoding="utf-8") as file:
            file.write("timeout: [1, 2\n")
        with self.assertRaises(ConfigError):
            SandboxConfig.from_yaml_file(path)

    def test_yaml_without_pyyaml_explains_the_way_out(self) -> None:
        path = os.path.join(self.dir.name, "asmx.yaml")
        with open(path, "w", encoding="utf-8") as file:
            file.write("timeout: 1\n")
        with unittest.mock.patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaises(ConfigError) as context:
                SandboxConfig.from_yaml_file(path)
        self.assertIn("PyYAML", str(context.exception))

    def test_save_and_read_json_again(self) -> None:
        path = os.path.join(self.dir.name, "new.json")
        SandboxConfig(timeout=4, workers=5).save(path)
        reread = SandboxConfig.from_file(path)
        self.assertEqual(reread.timeout, 4.0)
        self.assertEqual(reread.workers, 5)

    @unittest.skipUnless(HAS_YAML, "PyYAML is not installed")
    def test_save_yaml(self) -> None:
        path = os.path.join(self.dir.name, "new.yaml")
        SandboxConfig(timeout=6).save(path)
        with open(path, encoding="utf-8") as file:
            self.assertIn("timeout", file.read())

    def test_unknown_save_format(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig().save(os.path.join(self.dir.name, "x.ini"))


class TestEnvironment(unittest.TestCase):
    """Environment variables and the precedence order."""

    def test_from_env(self) -> None:
        with unittest.mock.patch.dict(
            os.environ, {"ASMX_TIMEOUT": "12", "ASMX_WORKERS": "7", "ASMX_STRICT": "1"}, clear=True
        ):
            config = SandboxConfig.from_env()
        self.assertEqual(config.timeout, 12.0)
        self.assertEqual(config.workers, 7)
        self.assertTrue(config.strict)

    def test_empty_variable_is_ignored(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"ASMX_TIMEOUT": ""}, clear=True):
            self.assertEqual(SandboxConfig.from_env().timeout, 30.0)

    def test_invalid_variable(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"ASMX_TIMEOUT": "lots"}, clear=True):
            with self.assertRaises(ConfigError):
                SandboxConfig.from_env()

    def test_environment_overrides_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "asmx.json")
            with open(path, "w", encoding="utf-8") as file:
                json.dump({"timeout": 5, "workers": 2}, file)
            with unittest.mock.patch.dict(os.environ, {"ASMX_WORKERS": "9"}, clear=True):
                config = SandboxConfig.load(path)
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.workers, 9)

    def test_indicated_file_that_does_not_exist(self) -> None:
        with self.assertRaises(ConfigError):
            SandboxConfig.load("/tmp/asmx_does_not_exist.json")

    def test_environment_variable_points_to_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "config.json")
            with open(path, "w", encoding="utf-8") as file:
                json.dump({"max_steps": 77}, file)
            with unittest.mock.patch.dict(os.environ, {CONFIG_ENV_VAR: path}, clear=True):
                self.assertEqual(SandboxConfig.load().max_steps, 77)

    def test_without_a_file_uses_the_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                config = SandboxConfig.load(start=folder)
        self.assertEqual(config.timeout, 30.0)


class TestFindFile(unittest.TestCase):
    """Automatic search of the configuration file."""

    def test_finds_it_in_the_indicated_directory(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, CANDIDATE_NAMES[0])
            with open(path, "w", encoding="utf-8") as file:
                file.write("timeout: 1\n")
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(SandboxConfig.find_file(folder), path)

    def test_nothing_found(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with unittest.mock.patch.dict(os.environ, {"HOME": folder}, clear=True):
                self.assertIsNone(SandboxConfig.find_file(folder))

    def test_environment_variable_has_priority(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "mine.json")
            with open(path, "w", encoding="utf-8") as file:
                file.write("{}")
            with unittest.mock.patch.dict(os.environ, {CONFIG_ENV_VAR: path}, clear=True):
                self.assertEqual(SandboxConfig.find_file(folder), path)


class TestApplyLogging(unittest.TestCase):
    """The configuration rules the logging."""

    def tearDown(self) -> None:
        reset_logging()

    def test_applies_level_and_format(self) -> None:
        import io

        state = SandboxConfig(log_level="ERROR", log_json=True).apply_logging(io.StringIO())
        self.assertEqual(state.level, "ERROR")
        self.assertTrue(state.json_output)


if __name__ == "__main__":
    unittest.main()
