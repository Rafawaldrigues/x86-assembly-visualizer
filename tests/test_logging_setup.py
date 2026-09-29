"""Tests of the structured logging: formats, levels, environment and reconfiguration."""

import io
import json
import logging
import os
import tempfile
import unittest
import unittest.mock

from asmx.logging_setup import (
    LOGGER_NAME,
    LoggingState,
    TextFormatter,
    configure_logging,
    env_flag,
    get_logger,
    log_event,
    reset_logging,
    resolve_level,
)


class BaseLogging(unittest.TestCase):
    """Makes sure one case does not leave logging on for the next one."""

    def setUp(self) -> None:
        reset_logging()

    def tearDown(self) -> None:
        reset_logging()

    def capture(self, level: str = "DEBUG", **kwargs: object) -> io.StringIO:
        stream = io.StringIO()
        configure_logging(level, json_output=True, stream=stream, force=True, **kwargs)
        return stream


class TestLevels(unittest.TestCase):
    """Level name conversion and boolean environment variable reading."""

    def test_lowercase_name(self) -> None:
        self.assertEqual(resolve_level("debug"), logging.DEBUG)

    def test_number_passes_through(self) -> None:
        self.assertEqual(resolve_level(42), 42)

    def test_none_becomes_info(self) -> None:
        self.assertEqual(resolve_level(None), logging.INFO)

    def test_invalid_name_explains(self) -> None:
        with self.assertRaises(ValueError) as context:
            resolve_level("noisy")
        self.assertIn("DEBUG", str(context.exception))

    def test_env_flag_truthy_values(self) -> None:
        for value in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=value):
                with unittest.mock.patch.dict(os.environ, {"ASMX_TEST": value}):
                    self.assertTrue(env_flag("ASMX_TEST"))

    def test_env_flag_falsy_values(self) -> None:
        for value in ("0", "false", "no", "off", ""):
            with self.subTest(value=value):
                with unittest.mock.patch.dict(os.environ, {"ASMX_TEST": value}):
                    self.assertFalse(env_flag("ASMX_TEST", default=True))

    def test_missing_env_flag_uses_the_default(self) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(env_flag("ASMX_DOES_NOT_EXIST", default=True))
            self.assertFalse(env_flag("ASMX_DOES_NOT_EXIST"))

    def test_strange_env_flag_text_uses_the_default(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"ASMX_TEST": "maybe"}):
            self.assertTrue(env_flag("ASMX_TEST", default=True))


class TestJsonFormatter(BaseLogging):
    """The JSON format is the contract for CI and for Docker."""

    def test_required_fields(self) -> None:
        stream = self.capture()
        get_logger("asmx.test").info("hello")
        data = json.loads(stream.getvalue())
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["logger"], "asmx.test")
        self.assertEqual(data["message"], "hello")
        self.assertRegex(data["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_one_line_per_event(self) -> None:
        stream = self.capture()
        log = get_logger("asmx.test")
        log.info("first")
        log.info("second")
        lines = stream.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_non_ascii_is_preserved(self) -> None:
        stream = self.capture()
        get_logger("asmx.test").warning("temperature 20\u00b0C")
        self.assertIn("temperature 20\u00b0C", stream.getvalue())

    def test_extra_fields_become_keys(self) -> None:
        stream = self.capture()
        log_event(get_logger("asmx.test"), "analysis_completed", instructions=12, blocks=4, ok=True)
        data = json.loads(stream.getvalue())
        self.assertEqual(data["event"], "analysis_completed")
        self.assertEqual(data["instructions"], 12)
        self.assertEqual(data["blocks"], 4)
        self.assertTrue(data["ok"])

    def test_protected_key_gets_a_prefix(self) -> None:
        stream = self.capture()
        get_logger("asmx.test").info("x", extra={"level": "high"})
        self.assertEqual(json.loads(stream.getvalue())["extra_level"], "high")

    def test_exception_enters_the_json(self) -> None:
        stream = self.capture()
        try:
            raise ValueError("broke on purpose")
        except ValueError:
            get_logger("asmx.test").error("failed", exc_info=True)
        data = json.loads(stream.getvalue())
        self.assertIn("ValueError", data["exception"])

    def test_value_that_is_not_serializable_becomes_text(self) -> None:
        stream = self.capture()
        log_event(get_logger("asmx.test"), "collection", names={"b", "a"})
        self.assertEqual(json.loads(stream.getvalue())["names"], "a,b")


class TestTextFormatter(BaseLogging):
    """The text format is the one that shows up in the terminal."""

    def test_shows_event_and_extras(self) -> None:
        stream = io.StringIO()
        configure_logging("INFO", json_output=False, stream=stream, force=True)
        log_event(get_logger("asmx.test"), "check_finished", errors=0)
        line = stream.getvalue()
        self.assertIn("check_finished", line)
        self.assertIn("event=check_finished", line)
        self.assertIn("errors=0", line)

    def test_without_extras(self) -> None:
        formatter = TextFormatter(show_extras=False)
        record = logging.LogRecord("asmx.test", logging.INFO, __file__, 1, "hi", None, None)
        self.assertNotIn("event=", formatter.format(record))

    def test_exception_shows_up(self) -> None:
        stream = io.StringIO()
        configure_logging("INFO", json_output=False, stream=stream, force=True)
        try:
            raise KeyError("vanished")
        except KeyError:
            get_logger("asmx.test").error("failed", exc_info=True)
        self.assertIn("KeyError", stream.getvalue())


class TestConfigureLogging(BaseLogging):
    """Configuration, reconfiguration and the returned state."""

    def test_state_returned(self) -> None:
        state = configure_logging("DEBUG", json_output=True, stream=io.StringIO(), force=True)
        self.assertIsInstance(state, LoggingState)
        self.assertEqual(state.level, "DEBUG")
        self.assertTrue(state.json_output)
        self.assertEqual(state.handlers, 1)
        self.assertEqual(state.to_dict()["handlers"], 1)

    def test_does_not_duplicate_the_handler(self) -> None:
        configure_logging("INFO", stream=io.StringIO(), force=True)
        first = configure_logging("INFO", stream=io.StringIO())
        self.assertEqual(first.handlers, 1)
        self.assertEqual(len(logging.getLogger(LOGGER_NAME).handlers), 1)

    def test_force_reconfigures(self) -> None:
        configure_logging("INFO", json_output=False, stream=io.StringIO(), force=True)
        state = configure_logging("ERROR", json_output=True, stream=io.StringIO(), force=True)
        self.assertEqual(state.level, "ERROR")
        self.assertTrue(state.json_output)

    def test_level_comes_from_the_environment(self) -> None:
        with unittest.mock.patch.dict(
            os.environ, {"ASMX_LOG_LEVEL": "WARNING", "ASMX_LOG_JSON": "1"}
        ):
            state = configure_logging(stream=io.StringIO(), force=True)
        self.assertEqual(state.level, "WARNING")
        self.assertTrue(state.json_output)

    def test_log_file_receives_the_lines(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "asmx.log")
            config = configure_logging(
                "INFO", json_output=True, log_file=path, stream=io.StringIO(), force=True
            )
            get_logger("asmx.test").info("written to the file")
            logging.getLogger(LOGGER_NAME).handlers[1].flush()
            with open(path, encoding="utf-8") as file:
                content = file.read()
        self.assertEqual(config.handlers, 2)
        self.assertEqual(config.log_file, path)
        self.assertIn("written to the file", content)

    def test_invalid_level_raises(self) -> None:
        with self.assertRaises(ValueError):
            configure_logging("shouting", force=True)


class TestLogEvent(BaseLogging):
    """Structured events."""

    def test_event_without_a_message_uses_the_name(self) -> None:
        stream = self.capture()
        log_event(get_logger("asmx.test"), "started")
        self.assertEqual(json.loads(stream.getvalue())["message"], "started")

    def test_own_message(self) -> None:
        stream = self.capture()
        log_event(get_logger("asmx.test"), "started", message="started right now")
        self.assertEqual(json.loads(stream.getvalue())["message"], "started right now")

    def test_explicit_level(self) -> None:
        stream = self.capture()
        log_event(get_logger("asmx.test"), "detail", level=logging.DEBUG, x=1)
        self.assertEqual(json.loads(stream.getvalue())["level"], "DEBUG")

    def test_message_field_does_not_duplicate(self) -> None:
        stream = self.capture()
        log_event(get_logger("asmx.test"), "event", message="text")
        data = json.loads(stream.getvalue())
        self.assertNotIn("extra_message", data)


class TestGetLogger(unittest.TestCase):
    """The logger namespace is always asmx.*."""

    def test_module_name(self) -> None:
        self.assertEqual(get_logger("asmx.parser").name, "asmx.parser")

    def test_bare_name_gets_the_prefix(self) -> None:
        self.assertEqual(get_logger("parser").name, "asmx.parser")

    def test_no_name_is_the_project_root(self) -> None:
        self.assertEqual(get_logger().name, LOGGER_NAME)


class TestResetLogging(BaseLogging):
    """Turning logging off returns the namespace to its initial state."""

    def test_removes_handlers_and_propagates_again(self) -> None:
        configure_logging("INFO", stream=io.StringIO(), force=True)
        reset_logging()
        logger = logging.getLogger(LOGGER_NAME)
        self.assertEqual(logger.handlers, [])
        self.assertTrue(logger.propagate)

    def test_without_a_handler_nothing_is_printed(self) -> None:
        stream = io.StringIO()
        reset_logging()
        with unittest.mock.patch("sys.stderr", stream):
            get_logger("asmx.test").info("silence")
        self.assertEqual(stream.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
