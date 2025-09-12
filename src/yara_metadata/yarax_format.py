import argparse
from pathlib import Path
from typing import Dict, List
import yara_x
import toml

from io import StringIO

def format_files(files: List[Path], config: Dict = {}):
    formatter = get_formatter(config)

    for file in files:
        with open(file, "r") as f:
            old_content = f.read()
            new_content = StringIO()
            formatter.format(StringIO(old_content), new_content)
            overwrite_file((file, old_content, new_content))

def overwrite_file(path: Path, old_content: str, new_content: str):
    if old_content != new_content:
        with path.open("wb") as file:
            file.write(new_content.encode())


def load_config(config_path: Path):
    if config_path.exists() and config_path.is_file():
        config = toml.load(config_path)
        return config
    else:
        return {}
    
def get_formatter(config: Dict):
    format_config = config.get("fmt", {})
    align_metadata = format_config.get("meta", {}).get("align_values", True)
    align_patterns = format_config.get("patterns", {}).get("align_values", True)
    indent_section_headers = format_config.get("rule", {}).get("indent_section_headers", True)
    indent_section_contents = format_config.get("rule", {}).get("indent_section_contents", True)
    indent_spaces = format_config.get("rule", {}).get("indent_spaces", 2)
    newline_before_curly_brace = format_config.get("rule", {}).get("newline_before_curly_brace", False)
    empty_line_before_section_header = format_config.get("rule", {}).get("empty_line_before_section_header", True)
    empty_line_after_section_header = format_config.get("rule", {}).get("empty_line_after_section_header", False)

    return yara_x.Formatter(
        align_metadata,
        align_patterns,
        indent_section_headers,
        indent_section_contents,
        indent_spaces,
        newline_before_curly_brace,
        empty_line_before_section_header,
        empty_line_after_section_header
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-C", type=Path, required=False)
    parser.add_argument("filenames", nargs="*", type=Path)
    args = parser.parse_args()

    config_path = args.C
    file_names: List[Path] = args.filenames
    config = load_config(config_path)

    format_files(file_names, config)