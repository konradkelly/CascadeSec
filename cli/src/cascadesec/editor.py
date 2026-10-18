"""Hand a fix's corrected file to the person's editor and read back what
they saved (docs/cli-spec.md §10, `edit`).

review-api takes the **whole file** (`edited_content`) and computes the
diff itself, so this module never makes one to send -- the diff it shows is
only for the person to confirm what they changed.

  - The file is written to a temporary directory under its own name, so the
    editor picks the right syntax for `main.tf` or `network.ts`.
  - Bytes go out and come back exactly: no newline translation, so a CRLF
    file stays CRLF and an LF one stays LF. A byte-order mark the editor
    adds to a file that had none is removed; it is not the person's change.
  - The editor is $VISUAL, then $EDITOR, then Notepad on Windows or vi
    elsewhere, as git chooses. A GUI editor that returns at once (VS Code
    without --wait) would read back an unchanged file, which reads as
    "nothing changed" -- so the message for that case says to add --wait.
  - The file is kept when anything after the editor fails, and its path is
    printed, so a rejected request does not cost the person their edit.
"""

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from cascadesec.errors import USAGE, CliError

BOM = "﻿"


def editor_command(env):
    command = env.get("VISUAL") or env.get("EDITOR")
    if command:
        # Windows paths keep their backslashes; POSIX shell quoting applies
        # elsewhere, as in git's core.editor.
        return shlex.split(command, posix=os.name != "nt")
    return ["notepad"] if os.name == "nt" else ["vi"]


class Draft:
    """The fix's file, on disk for the editor."""

    def __init__(self, repo_path, content):
        self.original = content
        self.dir = Path(tempfile.mkdtemp(prefix="cascadesec-edit-"))
        # Only the base name: the repository path is the API's, and must not
        # become a path on this machine.
        self.path = self.dir / (PurePosixPath(repo_path).name or "fix.txt")
        self.path.write_bytes(content.encode("utf-8"))

    def open(self, env, run=subprocess.run):
        command = editor_command(env) + [str(self.path)]
        try:
            result = run(command)
        except OSError as e:
            raise CliError(f"could not start the editor {command[0]!r}: {e}. Set VISUAL or EDITOR, "
                           f"or pass --file. The fix's file is at {self.path}", USAGE) from None
        if result.returncode != 0:
            raise CliError(f"the editor exited with {result.returncode}; nothing was recorded. "
                           f"Your copy is at {self.path}", USAGE)
        return self.read()

    def read(self):
        try:
            text = self.path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise CliError(f"{self.path} is not UTF-8 any more; save it as UTF-8 and pass it "
                           "with --file", USAGE) from None
        if text.startswith(BOM) and not self.original.startswith(BOM):
            text = text[len(BOM):]
        return text

    def discard(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def read_prepared(path):
    """`--file`: the edited file, as prepared by a script or by hand."""
    try:
        return Path(path).read_bytes().decode("utf-8")
    except OSError as e:
        raise CliError(f"cannot read {path}: {e.strerror or e}", USAGE) from None
    except UnicodeDecodeError:
        raise CliError(f"{path} is not UTF-8", USAGE) from None
