import argparse
from codecs import ignore_errors
from collections import defaultdict
from dataclasses import dataclass
import datetime
import os
from pathlib import Path
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
    process_commits(commits, ignored_hashes, files, created_tag, modified_tag, store_commit_hash)

def update_metadata(file_path: Path, last_modified: date, created_on: date, created_tag: str, modified_tag: str, store_commit_hash: bool, commit_hash: str):
    updated = False
    updates = []
    try:
        yara_file = ym.parse_file(str(file_path))
    except yaramod.ParserError:
        print(f'Failed to parse {file_path}, please add the following metadata manually, if needed: {created_tag} = "{created_on}", {modified_tag} = "{last_modified}", "commit_hash" = "{commit_hash}"')
        return
    for rule in yara_file.rules:
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

    if args.initial:
        initial_run(file_names, created_tag, modified_tag, ignored_hashes, store_commit_hash)
        return
    current_date = date.today()
    branch_from = os.environ.get("YARA_METADATA_BRANCH_FROM")
    branch_to = os.environ.get("YARA_METADATA_BRANCH_TO")
    if branch_from and branch_to:
        merge_run(branch_from, branch_to, ignored_hashes, file_names, created_tag, modified_tag, store_commit_hash)
    else:
        yara_files = get_yara_files(args.filenames)
        for file in yara_files:
            repo = Repo(".")
            commit = repo.commit()
            update_metadata(file, current_date, current_date, created_tag, modified_tag, store_commit_hash, commit.hexsha)

def overwrite_file(path: Path, new_content: str):
    with path.open("r") as file:
        current_content = file.read()
    if current_content != new_content:
        with path.open("wb") as file:
            file.write(new_content.encode())

if __name__ == "__main__":
    main()