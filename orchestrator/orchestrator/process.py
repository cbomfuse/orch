"""Subprocess execution with timeouts, duration and log capture."""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

log = logging.getLogger("orchestrator.process")


@dataclass
class CommandResult:
    argv: list
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    cwd: Optional[str] = None
    log_path: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def summary(self, limit: int = 2000) -> str:
        tail = (self.stderr or self.stdout or "")[-limit:]
        return f"exit={self.returncode} timed_out={self.timed_out} duration={self.duration_seconds:.1f}s\n{tail}"


def which(binary: str) -> Optional[str]:
    from shutil import which as _which
    return _which(binary)


def run_command(argv: Sequence[str], *, cwd: Optional[os.PathLike | str] = None,
                env: Optional[Mapping[str, str]] = None, timeout: Optional[float] = None,
                log_path: Optional[os.PathLike | str] = None, input_text: Optional[str] = None,
                check: bool = False, stdout_path: Optional[os.PathLike | str] = None) -> CommandResult:
    """Run ``argv`` and capture everything.  Never raises on non-zero exit unless ``check``.

    With ``stdout_path`` the child's standard output goes byte-for-byte into that file instead of being
    captured (for tools that print their CBOM on stdout); the log then records the file and its size.
    """
    argv = [str(a) for a in argv]
    merged_env = dict(os.environ)
    if env:
        merged_env.update({k: str(v) for k, v in env.items()})
    log.debug("$ %s (cwd=%s)", " ".join(shlex.quote(a) for a in argv), cwd)
    sink = None
    if stdout_path:
        Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
        sink = open(stdout_path, "wb")
    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(argv, cwd=cwd, env=merged_env, input=input_text,
                              stdout=sink if sink is not None else subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout, errors="replace")
        rc, out, err = proc.returncode, proc.stdout or "", proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = None
        out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    except FileNotFoundError as exc:
        rc, out, err = 127, "", f"{argv[0]}: not found ({exc})"
    finally:
        if sink is not None:
            sink.close()
    duration = time.monotonic() - start
    result = CommandResult(argv, rc, out, err, duration, timed_out, str(cwd) if cwd else None)
    if stdout_path:
        result.extra["stdoutPath"] = str(stdout_path)
        result.extra["stdoutBytes"] = Path(stdout_path).stat().st_size
    if log_path:
        p = Path(log_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(f"$ {' '.join(shlex.quote(a) for a in argv)}\n")
            fh.write(f"# cwd={cwd} exit={rc} timed_out={timed_out} duration={duration:.2f}s\n")
            if stdout_path:
                fh.write(f"--- stdout -> {stdout_path} ({result.extra['stdoutBytes']} bytes) ---\n")
            if out:
                fh.write("--- stdout ---\n" + out + ("\n" if not out.endswith("\n") else ""))
            if err:
                fh.write("--- stderr ---\n" + err + ("\n" if not err.endswith("\n") else ""))
            fh.write("\n")
        result.log_path = str(p)
    if check and not result.ok:
        raise RuntimeError(f"command failed: {' '.join(argv)}\n{result.summary()}")
    return result
