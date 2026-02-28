from os import environ
import sys
from rich.align import Align
import yaml
from enum import Enum
from collections import Counter
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.prompt import Prompt
from rich.theme import Theme

class QuestionType(Enum):
    DEFAULT = 0
    ARRAY = 1
    MULTI = 2

class NumberingType(Enum):
    GLOBAL = 0
    SECTION = 1

QUESTION_TYPE_MAPPING = {
    "default": QuestionType.DEFAULT,
    "array": QuestionType.ARRAY,
    "multi": QuestionType.MULTI,
}

NUMBERING_TYPE_MAPPING = {
    "global": NumberingType.GLOBAL,
    "section": NumberingType.SECTION,
}

class GlobalConfig:
    def __init__(self, data):
        # Configuration Section
        cfg = data.get("config", {})
        self.flag = cfg.get("flag", environ.get("FLAG", "Flag is missing!"))
        self.can_skip = cfg.get("can_skip", False)
        self.array_delimiter = cfg.get("array_delimiter", ",")
        self.case_sensitive = cfg.get("case_sensitive", True)
        self.header_text = cfg.get("header_text", "")
        self.win_text = cfg.get("win_text", "")
        self.numbering = NUMBERING_TYPE_MAPPING.get(cfg.get("numbering", "global"), NumberingType.GLOBAL)
        
        # UI Styling Section
        ui = data.get("ui", {})
        self.panel_style = ui.get("panel_style", "blue")
        self.header_style = ui.get("header_style", "bold cyan")
        self.section_style = ui.get("section_style", "yellow")
        self.border_type = ui.get("border_type", "heavy")
        
        # Theme Section
        self.theme = Theme(data.get("theme", {
            "info": "cyan",
            "error": "bold red",
            "success": "bold green",
            "question": "bold white",
            "prompt": "bold yellow"
        }))
        
        sections = []
        length = 0
        if "sections" in data:
            for section in data["sections"]:
                questions = section.get("questions", [])
                sections.append(Section(
                    section.get("name", ""),
                    questions,
                    section.get("style", self.section_style)
                ))
                length += len(questions)
        elif "questions" in data:
            questions = data.get("questions", [])
            sections.append(Section(
                None,
                questions,
                None
            ))
            length += len(questions)
        self.sections = sections
        self.length = length

        self.all_correct = True

class Section:
    def __init__(self, name, questions, style):
        self.name = name
        self.questions = questions
        self.style = style
        self.length = len(questions)

class Question:
    def __init__(self, number, data, global_cfg):
        self.number = number
        self.question = data.get("question", "")
        q_cfg = data.get("config", {})
        
        self.case_sensitive = q_cfg.get("case_sensitive", global_cfg.case_sensitive)
        self.format = q_cfg.get("format", "")
        self.type = QUESTION_TYPE_MAPPING.get(q_cfg.get("type", "default"), QuestionType.DEFAULT)
        
        # Answer Processing
        raw_ans = data.get("answer", "")
        if not self.case_sensitive:
            if isinstance(raw_ans, list):
                self.answer = [a.casefold() for a in raw_ans]
            else:
                self.answer = raw_ans.casefold()
        else:
            self.answer = raw_ans

if __name__ == "__main__":
    try:
        with open("config.yaml", "r") as f:
            yaml_data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading YAML: {e}")
        sys.exit(1)

    config = GlobalConfig(yaml_data)
    console = Console(theme=config.theme, force_terminal=True, color_system="standard")
    
    # Header
    if config.header_text:
        console.print("\n")
        console.print(Panel(f"[{config.header_style}]{config.header_text}[/{config.header_style}]", 
                            border_style="bright_black", padding=(0,5)), justify="center")
        console.print("\n")

    # Main Loop
    q_counter = 0
    for i, section in enumerate(config.sections):
        if section.name:
            if i > 0:
                console.print("\n")
            console.print(Panel(Align.center(section.name), style=section.style, padding=(1,1)))

        for i, q_data in enumerate(section.questions, 1):
            q = Question(i, q_data, config)
            q_counter += 1
            
            q_number = 0
            if config.numbering == NumberingType.SECTION:
                q_number = q.number
                length = section.length
            else:
                q_number = q_counter
                length = config.length

            console.print(Rule(f"[info]Question {q_number} / {length}[/info]"))
            
            display_text = f"[question]{q.question}[/question]"
            if q.format:
                display_text += f"\n\n[dim]Format: {q.format}[/dim]"
                
            console.print(Panel(display_text, border_style=config.panel_style, box=getattr(sys.modules['rich.box'], config.border_type.upper())))

            user_input = Prompt.ask("[prompt]>[/prompt] Answer").strip()
            check_val = user_input.casefold() if not q.case_sensitive else user_input

            # Validation Logic
            correct = False
            if q.type == QuestionType.ARRAY:
                user_arr = [ans.strip() for ans in check_val.split(config.array_delimiter)]
                correct = Counter(user_arr) == Counter(q.answer)
            elif q.type == QuestionType.MULTI:
                correct = check_val in q.answer
            else:
                correct = check_val == q.answer

            if correct:
                console.print("[success]✔ CORRECT[/success]\n")
            else:
                console.print("[error]✘ INCORRECT[/error]\n")
                config.all_correct = False
                if not config.can_skip:
                    sys.exit(0)

    # Win State
    if config.all_correct:
        console.print(Rule("[success]Success![/success]"))
        if config.win_text:
            console.print(f"\n[info]{config.win_text}[/info]\n", justify="center")
    
        console.print(config.flag, justify="center", soft_wrap=True, highlight=False)
