import argparse
from collections import defaultdict
from dataclasses import dataclass
import datetime
from io import BytesIO
import os
from pathlib import Path
import tempfile
from typing import List
from git import Repo, Commit
from git.types import Files_TD
import yaramod
from datetime import date

ym = yaramod.Yaramod(yaramod.Features.AllCurrent)

def get_yara_files(files: list[Path]):
    return [file for file in files if file.suffix in [".yara", ".yar"]]

@dataclass
class CommitDate:
    date: datetime.date
    commit: Commit

@dataclass
class YaraFile:
    file_name: str
    file_path: str
    last_modified: CommitDate
    created_on: CommitDate
    file: Files_TD

def initial_run(files: List[Path], created_tag: str, modified_tag: str, ignored_hashes: List[str] = [], store_commit_hash=False):
    print(f"Running in initial mode on all commits")
    repo = Repo(".")
    process_commits([commit for commit in repo.iter_commits()], ignored_hashes, files, created_tag, modified_tag, store_commit_hash)

def process_commits(commits: List[Commit], ignored_hashes: List[str], files: List[Path], created_tag: str, modified_tag: str, store_commit_hash: bool):
    files = get_yara_files(files)
    yara_files = defaultdict[str, YaraFile](YaraFile)
    current_paths = {file.name: file for file in files}
    file_names = [file.name for file in files]
    for commit in commits:
        if commit.hexsha in ignored_hashes:
            continue
        commit_date = datetime.date.fromtimestamp(commit.authored_date)
        for path, file_name, value in [(key, Path(key).name, value) for key, value in commit.stats.files.items() if Path(key).name in file_names and (key.endswith(".yara") or key.endswith(".yar"))]:
            if not file_name in yara_files:
                yara_files[file_name] = YaraFile(file_name, current_paths[file_name], CommitDate(commit_date, commit), CommitDate(commit_date, commit), value)
            else:
                yara_files[file_name].created_on.date = commit_date
                yara_files[file_name].created_on.commit = commit
                yara_files[file_name].file = value
    for yara_file in yara_files.values():
        update_metadata(yara_file.file_path, yara_file.last_modified.date, yara_file.created_on.date, created_tag, modified_tag, store_commit_hash, yara_file.last_modified.commit.hexsha)


def merge_run(branch_from: str, branch_to: str, ignored_hashes: List[str], files: List[Path], created_tag, modified_tag, store_commit_hash):
    repo = Repo(".")
    commits = repo.git.rev_list(f"{branch_from}..{branch_to}")
    commits = [commit for commit in repo.iter_commits() if commit.hexsha in commits]
    print(f"Running in merge mode with from: {branch_from}, to: {branch_to}.  Processing {len(commits)} commits.")
    process_commits(commits, ignored_hashes, files, created_tag, modified_tag, store_commit_hash)

def compare_rule(a: yaramod.Rule, b: yaramod.Rule, modified_tag: str):
    a_meta = a.get_meta_with_name(modified_tag)
    b_meta = b.get_meta_with_name(modified_tag)
    a_modified = a_meta.value.string
    b_modified = b_meta.value.string
    a_meta.value = yaramod.Literal("")
    b_meta.value = yaramod.Literal("")
    match = a.text == b.text
    a_meta.value = yaramod.Literal(a_modified)
    b_meta.value = yaramod.Literal(b_modified)
    return match

def process_rules(file_path: Path, yara_file: YaraFile, old_yara_file: YaraFile, created_tag: str, created_on: str, modified_tag: str, last_modified: str, commit_hash: str, store_commit_hash: bool):
    updated = False
    updates = []
    for rule in yara_file.rules:
        old_rule = [old_rule for old_rule in old_yara_file.rules if rule.name == old_rule.name]
        if old_rule:
            if compare_rule(rule, old_rule[0], modified_tag):
                continue
        if not rule.get_meta_with_name(created_tag):
            updated = True
            updates.append(f"Created: {created_tag}, with value: {str(created_on)}")
            rule.add_meta(created_tag, yaramod.Literal(str(created_on)))
        if meta :=rule.get_meta_with_name(modified_tag):
            if meta.value.string != str(last_modified):
                updated = True
                updates.append(f"Updated: {modified_tag}, with value: {str(last_modified)}")
                meta.value = yaramod.Literal(str(last_modified))
        else:
            updated = True
            updates.append(f"Created: {modified_tag}, with value: {str(last_modified)}")
            rule.add_meta(modified_tag, yaramod.Literal(str(last_modified)))
        if store_commit_hash:
            if meta :=rule.get_meta_with_name("commit_hash"):
                if meta.value != str(commit_hash):
                    updated = True
                    updates.append(f"Updated: commit_hash, with value: {str(commit_hash)}")
                    meta.value = yaramod.Literal(str(commit_hash))
            else:
                updated = True
                updates.append(f"Created: commit_hash, with value: {str(commit_hash)}")
                rule.add_meta("commit_hash", yaramod.Literal(str(commit_hash)))
    if updated:
        print(f'Updating {file_path}: {updates}')
        overwrite_file(Path(file_path), yara_file.text_formatted)


def update_metadata(file_path: Path, last_modified: date, created_on: date, created_tag: str, modified_tag: str, store_commit_hash: bool, commit_hash: str, old_content: bytes):
    try:
        yara_file = ym.parse_file(str(file_path))
        with tempfile.TemporaryFile("wb", suffix=".yara", delete=False) as output_file:
            output_file.write(old_content)
            output_file.close()
            old_yara_file = ym.parse_file(output_file.name)
            process_rules(file_path, yara_file, old_yara_file, created_tag, created_on, modified_tag, last_modified, commit_hash, store_commit_hash)
            os.unlink(output_file.name)
    except yaramod.ParserError:
        print(f'Failed to parse {file_path}, please add the following metadata manually, if needed: {created_tag} = "{created_on}", {modified_tag} = "{last_modified}", "commit_hash" = "{commit_hash}"')
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--initial", action="store_true")
    parser.add_argument("--hash", action="store_true", help="Put last modified commit hash in metadata.", default=False)
    parser.add_argument("--ignored-hashes", action="append", type=str, default=[], help="Ignore these commit hashes, useful for commits where the project is restructured.")
    parser.add_argument("--created-tag", type=str, default="created_on")
    parser.add_argument("--modified-tag", type=str, default="last_modified")
    parser.add_argument("filenames", nargs="*", type=Path)
    args = parser.parse_args()

    created_tag = args.created_tag
    modified_tag = args.modified_tag
    ignored_hashes = args.ignored_hashes
    store_commit_hash = args.hash
    file_names: List[Path] = args.filenames


    current_date = date.today()
    branch_from = os.environ.get("YARA_METADATA_BRANCH_FROM")
    branch_to = os.environ.get("YARA_METADATA_BRANCH_TO")
    if args.initial:
        initial_run(file_names, created_tag, modified_tag, ignored_hashes, store_commit_hash)
    elif branch_from and branch_to:
        merge_run(branch_from, branch_to, ignored_hashes, file_names, created_tag, modified_tag, store_commit_hash)
    else:
        yara_files = get_yara_files(args.filenames)
        print(f"Running in local mode on {len(yara_files)} files")
        for file in yara_files:
            repo = Repo(".")
            commit = repo.commit()
            old_file = commit.parents[0].tree / str(file).replace("\\", "/")
            old_content = BytesIO(old_file.data_stream.read()).getvalue()
            update_metadata(file, current_date, current_date, created_tag, modified_tag, store_commit_hash, commit.hexsha, old_content)

def overwrite_file(path: Path, new_content: str):
    with path.open("r") as file:
        current_content = file.read()
    if current_content != new_content:
        with path.open("wb") as file:
            file.write(new_content.encode())

if __name__ == "__main__":
    main()