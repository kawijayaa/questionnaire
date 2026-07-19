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

from server import AppConfig, main


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


class RenderingTests(unittest.TestCase):
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
                patch("server.Prompt.ask", return_value="answer"),
                redirect_stdout(output),
            ):
                main()

        rendered = output.getvalue()
        self.assertEqual(rendered.count(marker), 6)
        self.assertIn(f"CTF{{{marker}}}", rendered)


if __name__ == "__main__":
    unittest.main()
