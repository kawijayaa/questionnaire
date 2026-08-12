import argparse
import os
import sys
import unicodedata
from collections import Counter
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import List, Optional, Union

import regex as regex_engine
import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, model_validator
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.theme import Theme

load_dotenv()


class QuestionType(str, Enum):
    DEFAULT = "default"
    ARRAY = "array"
    MULTI = "multi"
    REGEX = "regex"


class NumberingType(str, Enum):
    GLOBAL = "global"
    SECTION = "section"


class BorderType(str, Enum):
    ROUNDED = "rounded"
    HEAVY = "heavy"
    SQUARE = "square"
    DOUBLE = "double"
    ASCII = "ascii"


class ArrayDuplicatePolicy(str, Enum):
    PRESERVE = "preserve"
    IGNORE = "ignore"


class AnswerTooLongError(ValueError):
    pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ThemeConfig(StrictModel):
    info: str = "cyan"
    error: str = "bold red"
    success: str = "bold green"
    question: str = "bold white"
    prompt: str = "bold yellow"


class UIConfig(StrictModel):
    panel_style: str = "blue"
    header_style: str = "bold cyan"
    section_style: str = "yellow"
    border_type: BorderType = BorderType.HEAVY


class QuestionConfigOpts(StrictModel):
    type: QuestionType = QuestionType.DEFAULT
    case_sensitive: Optional[bool] = None
    subtext: str = ""
    format: str = ""


class QuestionModel(StrictModel):
    question: str
    answer: Union[str, List[str]]
    config: QuestionConfigOpts = Field(default_factory=QuestionConfigOpts)

    @model_validator(mode="after")
    def validate_answer(self) -> "QuestionModel":
        answer = self.answer
        question_type = self.config.type

        if question_type in (QuestionType.DEFAULT, QuestionType.REGEX):
            if not isinstance(answer, str) or not answer.strip():
                raise ValueError(f"{question_type.value} questions require a string answer")
        elif not isinstance(answer, list) or not answer:
            raise ValueError(
                f"{question_type.value} questions require a non-empty answer list"
            )
        elif any(not item.strip() for item in answer):
            raise ValueError("answer lists cannot contain empty or whitespace-only values")

        if question_type == QuestionType.REGEX:
            try:
                regex_engine.compile(answer)
            except regex_engine.error as error:
                raise ValueError(f"invalid regular expression: {error}") from error

        return self


class SectionModel(StrictModel):
    name: Optional[str] = None
    style: Optional[str] = None
    questions: List[QuestionModel] = Field(min_length=1)


class NormalizationConfig(StrictModel):
    trim_whitespace: bool = True
    collapse_whitespace: bool = False
    ignore_punctuation: bool = False
    numeric_comparison: bool = False
    array_duplicates: ArrayDuplicatePolicy = ArrayDuplicatePolicy.PRESERVE


class ConfigBlock(StrictModel):
    header_text: str = ""
    win_text: str = ""
    case_sensitive: bool = True
    can_skip: bool = False
    continue_on_incorrect: bool = False
    array_delimiter: str = ","
    numbering: NumberingType = NumberingType.GLOBAL
    normalization: NormalizationConfig = Field(default_factory=NormalizationConfig)
    max_answer_length: int = Field(default=4096, ge=1, le=1_000_000)
    regex_timeout_ms: int = Field(default=100, ge=1, le=10_000)

    @model_validator(mode="after")
    def validate_array_delimiter(self) -> "ConfigBlock":
        if not self.array_delimiter:
            raise ValueError("array_delimiter cannot be empty")
        return self


class AppConfig(StrictModel):
    config: ConfigBlock = Field(default_factory=ConfigBlock)
    ui: UIConfig = Field(default_factory=UIConfig)
    theme: ThemeConfig = Field(default_factory=ThemeConfig)
    sections: List[SectionModel] = Field(default_factory=list)
    questions: Optional[List[QuestionModel]] = None

    @model_validator(mode="after")
    def validate_question_source(self) -> "AppConfig":
        has_sections = bool(self.sections)
        has_questions = bool(self.questions)
        if has_sections == has_questions:
            raise ValueError("provide exactly one non-empty question source: sections or questions")

        try:
            theme = Theme(self.theme.model_dump())
            console = Console(theme=theme)
            styles = {
                "ui.panel_style": self.ui.panel_style,
                "ui.header_style": self.ui.header_style,
                "ui.section_style": self.ui.section_style,
            }
            styles.update(
                {
                    f"sections.{index}.style": section.style
                    for index, section in enumerate(self.sections)
                    if section.style is not None
                }
            )
            for location, style in styles.items():
                try:
                    console.get_style(style)
                except Exception as error:
                    raise ValueError(
                        f"invalid Rich style for {location}: {style!r}"
                    ) from error
        except ValueError:
            raise
        except Exception as error:
            raise ValueError(f"invalid theme style: {error}") from error

        return self


def normalize_text(value: str, config: NormalizationConfig, case_sensitive: bool) -> str:
    if config.trim_whitespace:
        value = value.strip()
    if config.ignore_punctuation:
        value = "".join(
            character
            for character in value
            if not unicodedata.category(character).startswith("P")
        )
    if config.collapse_whitespace:
        value = " ".join(value.split())
    if not case_sensitive:
        value = value.casefold()
    return value


def comparison_key(
    value: str, config: NormalizationConfig, case_sensitive: bool
) -> tuple[str, Union[str, Decimal]]:
    if config.numeric_comparison:
        numeric_candidates = [value]
        if config.ignore_punctuation:
            numeric_candidates.append(
                "".join(
                    character
                    for character in value
                    if not unicodedata.category(character).startswith("P")
                )
            )
        for candidate in numeric_candidates:
            if config.trim_whitespace:
                candidate = candidate.strip()
            if config.collapse_whitespace:
                candidate = " ".join(candidate.split())
            try:
                numeric_value = Decimal(candidate)
                if numeric_value.is_finite():
                    return ("number", numeric_value)
            except InvalidOperation:
                continue
    normalized = normalize_text(value, config, case_sensitive)
    return ("text", normalized)


def is_answer_correct(
    question: QuestionModel, user_input: str, config: ConfigBlock
) -> bool:
    """Return whether a prompt response satisfies a question."""
    is_case_sensitive = (
        question.config.case_sensitive
        if question.config.case_sensitive is not None
        else config.case_sensitive
    )

    if question.config.type == QuestionType.REGEX:
        regex_input = user_input
        if config.normalization.trim_whitespace:
            regex_input = regex_input.strip()
        if config.normalization.collapse_whitespace:
            regex_input = " ".join(regex_input.split())
        flags = 0 if is_case_sensitive else regex_engine.IGNORECASE
        try:
            return bool(
                regex_engine.match(
                    question.answer,
                    regex_input,
                    flags=flags,
                    timeout=config.regex_timeout_ms / 1000,
                )
            )
        except TimeoutError:
            return False

    if question.config.type == QuestionType.ARRAY:
        user_values = [
            comparison_key(item, config.normalization, is_case_sensitive)
            for item in user_input.split(config.array_delimiter)
        ]
        answer_values = [
            comparison_key(item, config.normalization, is_case_sensitive)
            for item in question.answer
        ]
        if config.normalization.array_duplicates == ArrayDuplicatePolicy.IGNORE:
            return set(user_values) == set(answer_values)
        return Counter(user_values) == Counter(answer_values)

    user_value = comparison_key(
        user_input, config.normalization, is_case_sensitive
    )
    if question.config.type == QuestionType.MULTI:
        return user_value in {
            comparison_key(item, config.normalization, is_case_sensitive)
            for item in question.answer
        }
    return user_value == comparison_key(
        question.answer, config.normalization, is_case_sensitive
    )


def load_config(config_path: str) -> AppConfig:
    with Path(config_path).open("r", encoding="utf-8") as config_file:
        yaml_data = yaml.safe_load(config_file)
    if not isinstance(yaml_data, dict):
        raise ValueError("configuration root must be a YAML mapping")
    return AppConfig(**yaml_data)


def read_answer(console: Console, prompt: str, max_length: int) -> str:
    """Read one terminal line without allocating beyond the configured limit."""
    console.print(prompt, end=": ")
    response = sys.stdin.readline(max_length + 2)
    if response == "":
        raise EOFError
    response = response.removesuffix("\n").removesuffix("\r")
    if len(response) > max_length:
        raise AnswerTooLongError
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description="Questionnaire Server")
    parser.add_argument(
        "-c", "--config", type=str, default="config.yaml", help="Path to config file"
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate the configuration and exit without requiring FLAG",
    )
    args = parser.parse_args()

    try:
        app_cfg = load_config(args.config)
    except Exception as error:
        print(f"Configuration Validation Error:\n{error}")
        sys.exit(1)

    if args.validate_config:
        print(f"Configuration is valid: {args.config}")
        return

    flag = os.environ.get("FLAG")
    if not flag:
        print(
            "Error: FLAG environment variable is not set. Please set it via "
            "environment variables or a .env file."
        )
        sys.exit(1)

    # Normalize sections (if root questions are provided instead of sections)
    sections = app_cfg.sections
    if not sections and app_cfg.questions:
        sections = [SectionModel(questions=app_cfg.questions)]

    # Calculate lengths
    total_questions = sum(len(s.questions) for s in sections)

    theme_dict = app_cfg.theme.model_dump()
    theme = Theme(theme_dict)
    console = Console(theme=theme, force_terminal=True, color_system="standard")

    # Header
    if app_cfg.config.header_text:
        console.print("\n")
        console.print(
            Panel(
                Text(app_cfg.config.header_text, style=app_cfg.ui.header_style),
                border_style="bright_black",
                padding=(0, 5),
            ),
            justify="center",
        )
        console.print("\n")

    # Main Loop
    q_counter = 0
    all_correct = True

    for i, section in enumerate(sections):
        if section.name:
            if i > 0:
                console.print("\n")
            sec_style = section.style or app_cfg.ui.section_style
            console.print(
                Panel(
                    Align.center(Text(section.name)), style=sec_style, padding=(1, 1)
                )
            )

        for j, q in enumerate(section.questions, 1):
            q_counter += 1

            if app_cfg.config.numbering == NumberingType.SECTION:
                q_number = j
                length = len(section.questions)
            else:
                q_number = q_counter
                length = total_questions

            console.print(Rule(Text(f"Question {q_number} / {length}", style="info")))

            display_text = Text(q.question, style="question")
            if q.config.subtext:
                display_text.append("\n\n")
                display_text.append(q.config.subtext, style="dim")
            if q.config.format:
                display_text.append("\n\n")
                display_text.append(f"Format: {q.config.format}", style="dim")

            border = getattr(
                sys.modules["rich.box"], app_cfg.ui.border_type.value.upper()
            )
            console.print(
                Panel(display_text, border_style=app_cfg.ui.panel_style, box=border)
            )

            try:
                prompt_text = "[prompt]>[/prompt] Answer"
                if app_cfg.config.can_skip:
                    prompt_text += " ([info]press Enter to skip[/info])"
                user_input = read_answer(
                    console, prompt_text, app_cfg.config.max_answer_length
                )
            except AnswerTooLongError:
                console.print(
                    f"\n[error]Answer exceeds the {app_cfg.config.max_answer_length} "
                    "character limit.[/error]"
                )
                sys.exit(1)
            except (EOFError, KeyboardInterrupt):
                console.print(
                    "\n[error]Input ended before the questionnaire was completed.[/error]"
                )
                sys.exit(1)

            if app_cfg.config.can_skip and not user_input.strip():
                console.print("[info]↷ SKIPPED[/info]\n")
                all_correct = False
                continue

            correct = is_answer_correct(q, user_input, app_cfg.config)

            if correct:
                console.print("[success]✔ CORRECT[/success]\n")
            else:
                console.print("[error]✘ INCORRECT[/error]\n")
                all_correct = False
                if not app_cfg.config.continue_on_incorrect:
                    console.print(Rule("[error]Questionnaire incomplete[/error]"))
                    sys.exit(1)

    # Win State
    if all_correct:
        console.print(Rule("[success]Success![/success]"))
        if app_cfg.config.win_text:
            console.print(
                Text(f"\n{app_cfg.config.win_text}\n", style="info"), justify="center"
            )

        console.print(Text(flag), justify="center", soft_wrap=True, highlight=False)
    else:
        console.print(Rule("[error]Questionnaire incomplete[/error]"))
        sys.exit(1)


if __name__ == "__main__":
    main()
