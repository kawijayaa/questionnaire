import argparse
import os
import re
import sys
from collections import Counter
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
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


class ThemeConfig(BaseModel):
    info: str = "cyan"
    error: str = "bold red"
    success: str = "bold green"
    question: str = "bold white"
    prompt: str = "bold yellow"


class UIConfig(BaseModel):
    panel_style: str = "blue"
    header_style: str = "bold cyan"
    section_style: str = "yellow"
    border_type: str = "heavy"


class QuestionConfigOpts(BaseModel):
    type: QuestionType = QuestionType.DEFAULT
    case_sensitive: Optional[bool] = None
    format: str = ""


class QuestionModel(BaseModel):
    question: str
    answer: Union[str, List[str]]
    config: QuestionConfigOpts = Field(default_factory=QuestionConfigOpts)


class SectionModel(BaseModel):
    name: Optional[str] = None
    style: Optional[str] = None
    questions: List[QuestionModel] = []


class ConfigBlock(BaseModel):
    header_text: str = ""
    win_text: str = ""
    case_sensitive: bool = True
    can_skip: bool = False
    array_delimiter: str = ","
    numbering: NumberingType = NumberingType.GLOBAL


class AppConfig(BaseModel):
    config: ConfigBlock = Field(default_factory=ConfigBlock)
    ui: UIConfig = Field(default_factory=UIConfig)
    theme: ThemeConfig = Field(default_factory=ThemeConfig)
    sections: List[SectionModel] = []
    questions: Optional[List[QuestionModel]] = None


def main() -> None:
    parser = argparse.ArgumentParser(description="Questionnaire Server")
    parser.add_argument(
        "-c", "--config", type=str, default="config.yaml", help="Path to config file"
    )
    args = parser.parse_args()

    flag = os.environ.get("FLAG")
    if not flag:
        print(
            "Error: FLAG environment variable is not set. Please set it via environment variables or a .env file."
        )
        sys.exit(1)

    try:
        with open(args.config, "r") as f:
            yaml_data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading YAML: {e}")
        sys.exit(1)

    try:
        app_cfg = AppConfig(**yaml_data)
    except Exception as e:
        print(f"Configuration Validation Error:\n{e}")
        sys.exit(1)

    # Normalize sections (if root questions are provided instead of sections)
    sections = app_cfg.sections
    if not sections and app_cfg.questions:
        sections = [SectionModel(questions=app_cfg.questions)]

    # Calculate lengths
    total_questions = sum(len(s.questions) for s in sections)

    theme_dict = (
        app_cfg.theme.dict()
        if hasattr(app_cfg.theme, "dict")
        else app_cfg.theme.model_dump()
    )
    theme = Theme(theme_dict)
    console = Console(theme=theme, force_terminal=True, color_system="standard")

    # Header
    if app_cfg.config.header_text:
        console.print("\n")
        console.print(
            Panel(
                f"[{app_cfg.ui.header_style}]{app_cfg.config.header_text}[/{app_cfg.ui.header_style}]",
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
                Panel(Align.center(section.name), style=sec_style, padding=(1, 1))
            )

        for j, q in enumerate(section.questions, 1):
            q_counter += 1

            if app_cfg.config.numbering == NumberingType.SECTION:
                q_number = j
                length = len(section.questions)
            else:
                q_number = q_counter
                length = total_questions

            console.print(Rule(f"[info]Question {q_number} / {length}[/info]"))

            display_text = f"[question]{q.question}[/question]"
            if q.config.format:
                display_text += f"\n\n[dim]Format: {q.config.format}[/dim]"

            border = getattr(
                sys.modules["rich.box"],
                app_cfg.ui.border_type.upper(),
                sys.modules["rich.box"].HEAVY,
            )
            console.print(
                Panel(display_text, border_style=app_cfg.ui.panel_style, box=border)
            )

            user_input = Prompt.ask("[prompt]>[/prompt] Answer").strip()

            is_case_sensitive = (
                q.config.case_sensitive
                if q.config.case_sensitive is not None
                else app_cfg.config.case_sensitive
            )
            check_val = user_input if is_case_sensitive else user_input.casefold()

            # Process Answers
            ans = q.answer
            if not is_case_sensitive:
                if isinstance(ans, list):
                    ans = [a.casefold() for a in ans]
                else:
                    ans = ans.casefold()

            # Validation Logic
            correct = False
            q_type = q.config.type
            if q_type == QuestionType.ARRAY:
                user_arr = [
                    a.strip() for a in check_val.split(app_cfg.config.array_delimiter)
                ]
                correct = Counter(user_arr) == Counter(ans)
            elif q_type == QuestionType.MULTI:
                correct = check_val in ans
            elif q_type == QuestionType.REGEX:
                correct = bool(re.match(ans, check_val))
            else:
                correct = check_val == ans

            if correct:
                console.print("[success]✔ CORRECT[/success]\n")
            else:
                console.print("[error]✘ INCORRECT[/error]\n")
                all_correct = False
                if not app_cfg.config.can_skip:
                    sys.exit(1)

    # Win State
    if all_correct:
        console.print(Rule("[success]Success![/success]"))
        if app_cfg.config.win_text:
            console.print(
                f"\n[info]{app_cfg.config.win_text}[/info]\n", justify="center"
            )

        console.print(flag, justify="center", soft_wrap=True, highlight=False)


if __name__ == "__main__":
    main()
