import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml
from pydantic import ValidationError
from rich.console import Console

from server import (
    AnswerTooLongError,
    AppConfig,
    ConfigBlock,
    QuestionModel,
    is_answer_correct,
    main,
    read_answer,
)


def question(question_type="default", answer="answer"):
    return {
        "question": "Question",
        "answer": answer,
        "config": {"type": question_type},
    }


class AppConfigTests(unittest.TestCase):
    def test_requires_questions(self):
        with self.assertRaisesRegex(ValidationError, "exactly one non-empty"):
            AppConfig()

    def test_rejects_both_question_sources(self):
        with self.assertRaisesRegex(ValidationError, "exactly one non-empty"):
            AppConfig(
                questions=[question()],
                sections=[{"questions": [question()]}],
            )

    def test_rejects_empty_sections(self):
        with self.assertRaises(ValidationError):
            AppConfig(sections=[{"name": "Empty", "questions": []}])

    def test_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            AppConfig(questions=[question()], config={"can_skp": True})

    def test_requires_list_for_multi_and_array_answers(self):
        for question_type in ("multi", "array"):
            with self.subTest(question_type=question_type):
                with self.assertRaisesRegex(ValidationError, "non-empty answer list"):
                    AppConfig(questions=[question(question_type, "answer")])

    def test_requires_string_for_default_and_regex_answers(self):
        for question_type in ("default", "regex"):
            with self.subTest(question_type=question_type):
                with self.assertRaisesRegex(ValidationError, "string answer"):
                    AppConfig(questions=[question(question_type, ["answer"])])

    def test_rejects_invalid_regex(self):
        with self.assertRaisesRegex(ValidationError, "invalid regular expression"):
            AppConfig(questions=[question("regex", "[")])

    def test_rejects_empty_array_delimiter(self):
        with self.assertRaisesRegex(ValidationError, "array_delimiter cannot be empty"):
            AppConfig(
                config={"array_delimiter": ""},
                questions=[question("array", ["answer"])],
            )

    def test_rejects_invalid_styles_and_borders(self):
        with self.assertRaisesRegex(ValidationError, "invalid Rich style"):
            AppConfig(
                questions=[question()],
                ui={"panel_style": "not a real style !!!"},
            )

        with self.assertRaises(ValidationError):
            AppConfig(questions=[question()], ui={"border_type": "typo"})

        with self.assertRaisesRegex(ValidationError, "invalid theme style"):
            AppConfig(
                questions=[question()], theme={"info": "not a real style !!!"}
            )

    def test_ui_styles_can_reference_the_configured_theme(self):
        config = AppConfig(
            questions=[question()],
            ui={"panel_style": "info"},
            theme={"info": "bold blue"},
        )
        self.assertEqual(config.ui.panel_style, "info")

    def test_rejects_whitespace_only_answers(self):
        with self.assertRaises(ValidationError):
            AppConfig(questions=[question(answer=" ")])

        with self.assertRaises(ValidationError):
            AppConfig(questions=[question("multi", ["answer", " "])])

    def test_rejects_invalid_runtime_limits(self):
        for config in (
            {"max_answer_length": 0},
            {"regex_timeout_ms": 0},
        ):
            with self.subTest(config=config), self.assertRaises(ValidationError):
                AppConfig(questions=[question()], config=config)


class AnswerMatchingTests(unittest.TestCase):
    def assert_answer(
        self, expected, answer, response, question_type="default", **config
    ):
        model = QuestionModel(**question(question_type, answer))
        self.assertEqual(
            is_answer_correct(model, response, ConfigBlock(**config)), expected
        )

    def test_default_matching_and_case_sensitivity(self):
        self.assert_answer(True, "answer", "answer")
        self.assert_answer(False, "answer", "ANSWER")
        self.assert_answer(True, "answer", "ANSWER", case_sensitive=False)

    def test_question_case_sensitivity_overrides_global_setting(self):
        model = QuestionModel(
            **{
                **question(answer="answer"),
                "config": {"case_sensitive": True},
            }
        )
        self.assertFalse(
            is_answer_correct(model, "ANSWER", ConfigBlock(case_sensitive=False))
        )

    def test_multi_matching(self):
        self.assert_answer(True, ["one", "two"], "two", "multi")
        self.assert_answer(False, ["one", "two"], "three", "multi")

    def test_array_matching_is_unordered_and_preserves_duplicates(self):
        self.assert_answer(True, ["one", "two"], "two, one", "array")
        self.assert_answer(False, ["one", "two", "two"], "one, two", "array")
        self.assert_answer(
            True,
            ["one", "two"],
            "TWO | ONE",
            "array",
            case_sensitive=False,
            array_delimiter="|",
        )

    def test_case_insensitive_regex_preserves_regex_operators(self):
        self.assert_answer(True, r"^\D+$", "ABC", "regex", case_sensitive=False)
        self.assert_answer(False, r"^\D+$", "123", "regex", case_sensitive=False)
        self.assert_answer(True, r"^abc$", "ABC", "regex", case_sensitive=False)

    def test_text_normalization_options(self):
        self.assert_answer(True, " answer ", "answer")
        self.assert_answer(
            True,
            "hello world",
            "  hello   world  ",
            normalization={"collapse_whitespace": True},
        )
        self.assert_answer(
            True,
            "Hello world",
            "hello, world!",
            case_sensitive=False,
            normalization={"ignore_punctuation": True},
        )
        self.assert_answer(
            True,
            "1.0",
            "1.00",
            normalization={"numeric_comparison": True},
        )
        self.assert_answer(
            True,
            "1,000",
            "1000.0",
            normalization={
                "ignore_punctuation": True,
                "numeric_comparison": True,
            },
        )

    def test_array_duplicate_policy_can_ignore_duplicates(self):
        self.assert_answer(
            True,
            ["one", "two", "two"],
            "one,two",
            "array",
            normalization={"array_duplicates": "ignore"},
        )

    def test_regex_timeout_is_treated_as_a_non_match(self):
        model = QuestionModel(**question("regex", "^answer$"))
        with patch("server.regex_engine.match", side_effect=TimeoutError):
            self.assertFalse(is_answer_correct(model, "answer", ConfigBlock()))


class RenderingTests(unittest.TestCase):
    def test_answer_reader_enforces_the_limit_while_reading(self):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False)
        with (
            patch("sys.stdin", io.StringIO("12345\n")),
            self.assertRaises(AnswerTooLongError),
        ):
            read_answer(console, "Answer", 3)

    def test_validate_config_does_not_require_a_flag(self):
        config = {"questions": [question()]}

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(
                    sys,
                    "argv",
                    ["server.py", "--config", str(config_path), "--validate-config"],
                ),
                redirect_stdout(output),
            ):
                main()

        self.assertIn("Configuration is valid", output.getvalue())

    def test_external_text_is_not_interpreted_as_markup(self):
        marker = "[/red]"
        config = {
            "config": {
                "header_text": f"Header {marker}",
                "win_text": f"Win {marker}",
            },
            "sections": [
                {
                    "name": f"Section {marker}",
                    "questions": [
                        {
                            "question": f"Question {marker}",
                            "answer": "answer",
                            "config": {"format": f"Format {marker}"},
                        }
                    ],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"FLAG": f"CTF{{{marker}}}"}),
                patch.object(sys, "argv", ["server.py", "--config", str(config_path)]),
                patch("server.read_answer", return_value="answer"),
                redirect_stdout(output),
            ):
                main()

        rendered = output.getvalue()
        self.assertEqual(rendered.count(marker), 6)
        self.assertIn(f"CTF{{{marker}}}", rendered)

    def test_question_subtext_is_rendered_as_plain_text(self):
        marker = "Note [/red]"
        config = {
            "questions": [
                {
                    **question(),
                    "config": {"subtext": marker},
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"FLAG": "CTF{test}"}),
                patch.object(sys, "argv", ["server.py", "--config", str(config_path)]),
                patch("server.read_answer", return_value="answer"),
                redirect_stdout(output),
            ):
                main()

        self.assertIn(marker, output.getvalue())

    def test_eof_exits_cleanly_without_traceback(self):
        config = {"questions": [question()]}

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"FLAG": "CTF{test}"}),
                patch.object(sys, "argv", ["server.py", "--config", str(config_path)]),
                patch("server.read_answer", side_effect=EOFError),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as exit_context,
            ):
                main()

        self.assertEqual(exit_context.exception.code, 1)
        self.assertIn("Input ended", output.getvalue())

    def test_empty_input_skips_without_marking_the_answer_incorrect(self):
        config = {
            "config": {"can_skip": True},
            "questions": [question()],
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"FLAG": "CTF{must_not_leak}"}),
                patch.object(sys, "argv", ["server.py", "--config", str(config_path)]),
                patch("server.read_answer", return_value=""),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as exit_context,
            ):
                main()

        self.assertEqual(exit_context.exception.code, 1)
        self.assertIn("Questionnaire incomplete", output.getvalue())
        self.assertIn("SKIPPED", output.getvalue())
        self.assertNotIn("INCORRECT", output.getvalue())
        self.assertNotIn("must_not_leak", output.getvalue())

    def test_continue_on_incorrect_is_independent_from_skipping(self):
        config = {
            "config": {"continue_on_incorrect": True},
            "questions": [question(), question(answer="second")],
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"FLAG": "CTF{must_not_leak}"}),
                patch.object(sys, "argv", ["server.py", "--config", str(config_path)]),
                patch("server.read_answer", side_effect=["wrong", "second"]),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as exit_context,
            ):
                main()

        self.assertEqual(exit_context.exception.code, 1)
        self.assertEqual(output.getvalue().count("INCORRECT"), 1)
        self.assertEqual(output.getvalue().count("CORRECT"), 2)

    def test_oversized_answers_are_rejected(self):
        config = {
            "config": {"max_answer_length": 3},
            "questions": [question()],
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"FLAG": "CTF{test}"}),
                patch.object(sys, "argv", ["server.py", "--config", str(config_path)]),
                patch("server.read_answer", side_effect=AnswerTooLongError),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as exit_context,
            ):
                main()

        self.assertEqual(exit_context.exception.code, 1)
        self.assertIn("character limit", output.getvalue())


if __name__ == "__main__":
    unittest.main()
