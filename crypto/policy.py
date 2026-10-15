"""Policy tokenizer, validator, and logical -> versioned rewrite (doc 03 Section 3).

Logical policy (display):  (DEPT_CSE and ROLE_FACULTY) or ROLE_HOD
Versioned policy (crypto): (DEPT_CSE_V1 and ROLE_FACULTY_V3) or ROLE_HOD_V1

Attribute names are uppercase letters, digits, and underscores only; "and"/"or"
are case-insensitive keywords. Anything else -- including injection-like
strings -- is rejected.
"""
import re
from typing import Dict, List, Set

_TOKEN_RE = re.compile(r"[()]|[A-Za-z_][A-Za-z0-9_]*")
_ATTR_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_OPERATORS = ("and", "or")


def tokenize(policy: str) -> List[str]:
    tokens: List[str] = []
    pos = 0
    for match in _TOKEN_RE.finditer(policy):
        gap = policy[pos:match.start()]
        if gap.strip():
            raise ValueError("invalid character in policy: %r" % gap)
        tokens.append(match.group(0))
        pos = match.end()
    if policy[pos:].strip():
        raise ValueError("invalid character in policy: %r" % policy[pos:])
    return tokens


def validate(policy: str, known_attributes: Set[str]) -> List[str]:
    """Raises ValueError on malformed syntax or an unknown attribute."""
    tokens = tokenize(policy)
    if not tokens:
        raise ValueError("empty policy")

    depth = 0
    expect_operand = True
    for tok in tokens:
        low = tok.lower()
        if tok == "(":
            if not expect_operand:
                raise ValueError("unexpected '(' in policy")
            depth += 1
        elif tok == ")":
            if expect_operand:
                raise ValueError("unexpected ')' in policy")
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced parentheses")
        elif low in _OPERATORS:
            if expect_operand:
                raise ValueError("unexpected operator %r in policy" % tok)
            expect_operand = True
        else:
            if not expect_operand:
                raise ValueError("expected an operator before %r" % tok)
            if not _ATTR_RE.match(tok):
                raise ValueError("invalid attribute name: %r" % tok)
            if tok not in known_attributes:
                raise ValueError("unknown attribute: %r" % tok)
            expect_operand = False

    if depth != 0:
        raise ValueError("unbalanced parentheses")
    if expect_operand:
        raise ValueError("policy ends with an operator")
    return tokens


def to_versioned(policy: str, known_attributes: Set[str], versions: Dict[str, int]) -> str:
    """Rewrites a validated logical policy to the versioned form actually encrypted under."""
    tokens = validate(policy, known_attributes)
    rewritten = []
    for tok in tokens:
        low = tok.lower()
        if tok in ("(", ")"):
            rewritten.append(tok)
        elif low in _OPERATORS:
            rewritten.append(low)
        else:
            version = versions.get(tok)
            if version is None:
                raise ValueError("no current version for attribute: %r" % tok)
            rewritten.append("%s_V%d" % (tok, version))

    out = ""
    for i, tok in enumerate(rewritten):
        if i == 0 or tok == ")" or rewritten[i - 1] == "(":
            out += tok
        else:
            out += " " + tok
    return out


_VERSIONED_SUFFIX_RE = re.compile(r"_V\d+$")


def to_logical(versioned_policy: str) -> str:
    """Inverse of to_versioned: strips the _V<n> suffix off every attribute.

    The re-key worker only receives the versioned policy of a file, but has to
    re-encrypt under the *current* versions, so it reduces back to logical form
    and re-applies to_versioned with fresh versions.
    """
    tokens = tokenize(versioned_policy)
    out = ""
    for i, tok in enumerate(tokens):
        low = tok.lower()
        if tok in ("(", ")") or low in _OPERATORS:
            piece = tok if tok in ("(", ")") else low
        else:
            piece = _VERSIONED_SUFFIX_RE.sub("", tok)
        if i == 0 or piece == ")" or tokens[i - 1] == "(":
            out += piece
        else:
            out += " " + piece
    return out
