"""The airlock: the only path between the driver and the reader cell.

Commands go down, typed values come up. Everything that comes up is checked
here, in plain code, before the driver can see it:

- booleans, bounded numbers
- hex hashes and addresses
- labels from fixed vocabularies (capa rule names, ATT&CK IDs, known API names,
  file format/arch, confidence, error codes) or from the driver's own choices
- handles like ``$func_4`` or ``$str_17`` that stand in for raw content the
  driver never sees

Nothing else crosses: no free text, no tool error messages, no reader
reasoning, no names the sample controls. A message that fails validation is
dropped and logged, never repaired. Every crossing is appended to the airlock
log. The airlock also assigns each result's evidence grade from where it came
from; the reader can't influence it.
"""

from __future__ import annotations

import json
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)

VOCAB = Path(__file__).resolve().parent / "vocab"
MAX_MESSAGE_BYTES = 32_000
MAX_LIST = 50


@lru_cache
def vocab(name: str) -> frozenset[str]:
    return frozenset((VOCAB / f"{name}.txt").read_text().split("\n")) - {""}


def _in(name: str):
    def check(v: str) -> str:
        if v not in vocab(name):
            raise ValueError(f"not in {name} vocabulary")
        return v
    return check


# --- Value types allowed to cross upward -----------------------------------------

HANDLE_KINDS = ("func", "str", "code", "imp", "note", "match")
Handle = Annotated[str, StringConstraints(strict=True, pattern=r"^\$(func|str|code|imp|note|match)_[0-9]{1,6}$")]
Hex = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{1,64}$")]
Address = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{1,16}$")]
CapaRule = Annotated[str, StringConstraints(strict=True, max_length=120), AfterValidator(_in("capa_rules"))]
AttackId = Annotated[str, StringConstraints(strict=True, pattern=r"^T[0-9]{4}(\.[0-9]{3})?$"), AfterValidator(_in("attack"))]
ApiName = Annotated[str, StringConstraints(strict=True, max_length=64), AfterValidator(_in("apis"))]
Count = Annotated[StrictInt, Field(ge=0, le=10_000_000)]
Ratio = Annotated[StrictFloat, Field(ge=0.0, le=8.0)]

FileFormat = Literal["pe", "elf", "macho", "other"]
Arch = Literal["x86", "x86_64", "arm", "arm64", "other"]
Confidence = Literal["high", "moderate", "low"]
ErrorCode = Literal["TIMEOUT", "PARSE_FAIL", "TOOL_ERROR", "NOT_FOUND", "BAD_ARGS", "REJECTED"]
Grade = Literal["A", "B", "C", "D"]
StringSource = Literal["static", "decoded", "stack", "tight"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


# --- Commands (down) -----------------------------------------------------------------
# Written by the trusted driver, so free text is allowed in a few arguments
# (a YARA rule, a search pattern, a question). Still size-capped.

class FileInfo(_Strict):
    cmd: Literal["file_info"]

class Imports(_Strict):
    cmd: Literal["imports"]

class CapaMatches(_Strict):
    cmd: Literal["capa_matches"]

class ListFunctions(_Strict):
    cmd: Literal["list_functions"]
    sort: Literal["size", "callees", "callers", "address"] = "size"
    limit: Annotated[StrictInt, Field(ge=1, le=MAX_LIST)] = 20

class Decompile(_Strict):
    cmd: Literal["decompile"]
    func: Handle

class Xrefs(_Strict):
    cmd: Literal["xrefs"]
    target: Handle

class SearchStrings(_Strict):
    cmd: Literal["search_strings"]
    pattern: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    source: Literal["static", "decoded", "all"] = "all"
    limit: Annotated[StrictInt, Field(ge=1, le=MAX_LIST)] = 20

class DecodedStrings(_Strict):
    cmd: Literal["decoded_strings"]
    limit: Annotated[StrictInt, Field(ge=1, le=MAX_LIST)] = 30

class YaraTest(_Strict):
    cmd: Literal["yara_test"]
    rule: Annotated[str, StringConstraints(min_length=10, max_length=4000)]

Choice = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_\-]+$")]

class AnswerSpec(_Strict):
    type: Literal["bool", "int", "choice", "handles"]
    choices: Annotated[list[Choice], Field(max_length=12)] = []
    min: StrictInt = 0
    max: Annotated[StrictInt, Field(le=1_000_000)] = 100

class AskReader(_Strict):
    cmd: Literal["ask_reader"]
    question: Annotated[str, StringConstraints(min_length=5, max_length=1000)]
    about: Annotated[list[Handle], Field(min_length=1, max_length=10)]
    answer: AnswerSpec

Command = Annotated[
    Union[FileInfo, Imports, CapaMatches, ListFunctions, Decompile, Xrefs, SearchStrings,
          DecodedStrings, YaraTest, AskReader],
    Field(discriminator="cmd"),
]
COMMAND = TypeAdapter(Command)


# --- Results (up) --------------------------------------------------------------------

class FileInfoResult(_Strict):
    format: FileFormat
    arch: Arch
    size: Count
    sha256: Hex
    sections: Count
    max_section_entropy: Ratio
    function_count: Count
    import_count: Count
    string_count: Count

class ImportsResult(_Strict):
    known: Annotated[list[ApiName], Field(max_length=500)]
    unknown: Annotated[list[Handle], Field(max_length=200)]

class CapaMatch(_Strict):
    rule: CapaRule
    attack: Annotated[list[AttackId], Field(max_length=10)]
    hits: Count

class CapaResult(_Strict):
    matches: Annotated[list[CapaMatch], Field(max_length=300)]

class FunctionRow(_Strict):
    func: Handle
    address: Address
    size: Count
    callees: Count
    callers: Count
    api_calls: Annotated[list[ApiName], Field(max_length=30)]

class ListFunctionsResult(_Strict):
    total: Count
    functions: Annotated[list[FunctionRow], Field(max_length=MAX_LIST)]

class DecompileResult(_Strict):
    code: Handle
    lines: Count
    api_calls: Annotated[list[ApiName], Field(max_length=60)]
    unknown_calls: Count
    callees: Annotated[list[Handle], Field(max_length=60)]
    xor_ops: Count
    loops: Count
    string_refs: Annotated[list[Handle], Field(max_length=60)]

class XrefsResult(_Strict):
    callers: Annotated[list[Handle], Field(max_length=MAX_LIST)]
    callees: Annotated[list[Handle], Field(max_length=MAX_LIST)]

class StringRow(_Strict):
    str: Handle
    source: StringSource
    length: Count
    entropy: Ratio

class StringsResult(_Strict):
    total: Count
    strings: Annotated[list[StringRow], Field(max_length=MAX_LIST)]

class YaraResult(_Strict):
    compiled: StrictBool
    matched: StrictBool
    rules_matched: Count
    matches: Annotated[list[Handle], Field(max_length=MAX_LIST)]

class ReaderResult(_Strict):
    answer: Union[StrictBool, StrictInt, Choice, Annotated[list[Handle], Field(max_length=10)]]
    confidence: Confidence
    note: Handle  # the reader's reasoning, stored for the human report only

RESULTS: dict[str, type[_Strict]] = {
    "file_info": FileInfoResult,
    "imports": ImportsResult,
    "capa_matches": CapaResult,
    "list_functions": ListFunctionsResult,
    "decompile": DecompileResult,
    "xrefs": XrefsResult,
    "search_strings": StringsResult,
    "decoded_strings": StringsResult,
    "yara_test": YaraResult,
    "ask_reader": ReaderResult,
}

# Evidence grade by source (Admiralty-style; see the verdict scheme). Assigned
# here, never by the cell or the reader.
GRADES: dict[str, Grade] = {
    "file_info": "A",        # structure computed by tools
    "imports": "A",
    "capa_matches": "A",     # deterministic rule matches
    "yara_test": "A",
    "list_functions": "B",   # Ghidra's interpretation
    "decompile": "B",
    "xrefs": "B",
    "decoded_strings": "B",  # FLOSS's emulation
    "search_strings": "D",   # attacker-writable content (usable as artifact, never testimony)
    "ask_reader": "C",       # a model's typed reading of untrusted content
}


class Rejected(Exception):
    """A message failed validation. It was dropped and logged."""

    def __init__(self, direction: str, reason: str):
        super().__init__(f"{direction}: {reason}")
        self.reason = reason


class Airlock:
    """Validates both directions, tracks known handles, and logs every crossing."""

    def __init__(self, log_path: str | Path | None = None):
        self.log_path = Path(log_path) if log_path else None
        self.known: set[str] = set()
        self.crossings = 0
        self.rejections = 0

    # -- down ---------------------------------------------------------------------
    def check_command(self, cmd: dict[str, Any]) -> dict[str, Any]:
        try:
            parsed = COMMAND.validate_python(cmd)
        except ValidationError as e:
            self._log("down", cmd, ok=False, reason=_summ(e))
            raise Rejected("down", _summ(e)) from None
        refs = _handles_in(parsed.model_dump())
        unknown = [h for h in refs if h not in self.known]
        if unknown:
            self._log("down", cmd, ok=False, reason=f"unknown handles {unknown}")
            raise Rejected("down", f"unknown handles {unknown}")
        if isinstance(parsed, AskReader) and parsed.answer.type == "choice" and len(parsed.answer.choices) < 2:
            self._log("down", cmd, ok=False, reason="choice answers need at least 2 choices")
            raise Rejected("down", "choice answers need at least 2 choices")
        out = parsed.model_dump()
        self._log("down", out, ok=True)
        return out

    # -- up -----------------------------------------------------------------------
    def check_result(self, cmd: dict[str, Any], raw: str | bytes) -> dict[str, Any]:
        """Validate the cell's reply to `cmd` (already checked with check_command)."""
        name = cmd["cmd"]
        try:
            if len(raw) > MAX_MESSAGE_BYTES:
                raise ValueError(f"message too large ({len(raw)} bytes)")
            msg = json.loads(raw)
            if not isinstance(msg, dict) or set(msg) - {"ok", "result", "error"}:
                raise ValueError("bad envelope")
            if msg.get("ok") is not True:
                error = TypeAdapter(ErrorCode).validate_python(msg.get("error"))
                out = {"ok": False, "error": error, "grade": None}
                self._log("up", out, ok=True, cmd=name)
                return out
            result = RESULTS[name].model_validate(msg.get("result"))
            data = result.model_dump()
            if name == "ask_reader":
                self._check_answer(cmd, data["answer"])
        except (ValidationError, ValueError, json.JSONDecodeError) as e:
            reason = _summ(e) if isinstance(e, ValidationError) else str(e)[:200]
            self._log("up", {"dropped_bytes": len(raw)}, ok=False, reason=reason, cmd=name)
            raise Rejected("up", reason) from None

        self.known.update(_handles_in(data))
        out = {"ok": True, "result": data, "grade": GRADES[name]}
        self._log("up", out, ok=True, cmd=name)
        return out

    def _check_answer(self, cmd: dict[str, Any], answer: Any) -> None:
        spec = cmd["answer"]
        t = spec["type"]
        if t == "bool" and not isinstance(answer, bool):
            raise ValueError("expected bool answer")
        if t == "int" and (isinstance(answer, bool) or not isinstance(answer, int) or not spec["min"] <= answer <= spec["max"]):
            raise ValueError("int answer missing or out of range")
        if t == "choice" and answer not in spec["choices"]:
            raise ValueError("answer is not one of the driver's choices")
        if t == "handles":
            if not isinstance(answer, list) or any(h not in cmd["about"] and h not in self.known for h in answer):
                raise ValueError("answer handles must be ones the driver already knows")

    # -- log ------------------------------------------------------------------------
    def _log(self, direction: str, payload: Any, ok: bool, reason: str = "", cmd: str = "") -> None:
        self.crossings += 1
        self.rejections += not ok
        if not self.log_path:
            return
        entry = {"t": round(time.time(), 3), "dir": direction, "ok": ok}
        if cmd:
            entry["cmd"] = cmd
        if reason:
            entry["reason"] = reason
        entry["payload"] = payload
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")


def _handles_in(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, str):
        if re.fullmatch(r"\$(func|str|code|imp|note|match)_[0-9]{1,6}", obj):
            found.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            found += _handles_in(v)
    elif isinstance(obj, list):
        for v in obj:
            found += _handles_in(v)
    return found


def _summ(e: ValidationError) -> str:
    # Field locations and error types only: never echo the offending input.
    return "; ".join(f"{'.'.join(map(str, err['loc']))}: {err['type']}" for err in e.errors()[:5])
