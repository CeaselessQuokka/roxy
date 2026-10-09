"""Luau syntax highlighting for the public site, done once on the server.

What this is
    `highlight(source)` turns Luau source text into HTML: the text, escaped, with `<span class="k">` style
    wrappers around the pieces a reader's eye looks for: keywords, strings, numbers, comments, built-in names,
    types and operators. `tokenize(source)` is the step before it: the source cut into `Token(kind, text)` pieces
    that join back to exactly the input. `CSS_CLASS` maps each `Kind` to its class name, and `SCOPE_CLASS` is the
    class of the `<code>` element around highlighted code, which site.css uses to scope the colors.

Why it exists
    The owner asked for colored Luau on the home page and in the user guide (2026-10-07). The strict CSP (plan
    9.2) allows no third-party scripts and no inline styles, and a highlighter running in the browser would add a
    script and its weight to every visit. Highlighting on the server costs nothing per visit: the guide is
    rendered and the home examples highlighted once per process, at startup. It also works without JavaScript and
    keeps the markup small: one-letter class names whose colors live in site.css, for both themes, and one span
    for a run of neighboring tokens of the same kind.

How it works
    A hand-written scanner reads the text left to right, one token at a time (a "lexer"). Most tokens can be
    recognized on their own: comments (`-- line` and long `--[[ ]]` or `--[==[ ]==]` comments), strings (quoted,
    long brackets `[[ ]]` and `[=[ ]=]`, and backtick strings whose `{expression}` parts are scanned again as
    code), numbers (decimal, hex `0xFF`, binary `0b1010`, `_` separators, exponents), names, attributes
    (`@native`) and operators. Three things need a little context, which the scanner keeps:
    - Contextual keywords. Luau added `continue`, `type`, `export` and `const` (Luau 0.711) without reserving
      them, so a script may still use them as names. `type Foo = ...` is a declaration but `type(value)` is the
      built-in function; `const x = 1` declares a constant but `print(const)` reads a variable; `continue` is a
      keyword only where another statement (or nothing) follows. Each rule looks at the next token to decide.
    - Types. Luau annotations reuse `:`, which also calls methods (`HttpService:GetAsync(url)`). A `:` followed by
      a name and then `(`, a string or `{` is a method call; any other `:` starts a type annotation. `::` casts,
      `type Name =` aliases and `<T>` after `function` or `function name` also start types. Inside a type, names
      are type names (`number`, `GameDetails`), `name:` inside braces or parentheses labels a field or parameter,
      and the type ends at the first token that cannot continue it (`=`, a `,` outside brackets, a new
      statement).
    - Built-ins. Roblox and Luau globals (`game`, `task`, `print`, `pcall`...) when they are not a field of
      something else, library calls as one piece (`string.lower`, `task.wait`), and well-known methods after
      `:` or `.` (`GetService`, `RequestAsync`, `JSONDecode`...).
    Total by construction: every step consumes at least one character or ends its loop, and every nesting (a
    backtick string inside an interpolation, `typeof(...)`, a bracket inside a type) goes one level deeper only
    while fewer than `MAX_NESTING` levels are open; deeper text is scanned flat as code or string text. So any
    text, however broken or hostile, is tokenized without raising and without exhausting Python's recursion
    limit, in time that grows linearly with its length. An unterminated string or comment simply runs to the
    end of its line or of the text.
    Safety: every piece of text goes through `html.escape` before it is written, and class names come only from
    the fixed `CSS_CLASS` table, never from the input. Joining the tokens gives back the input exactly
    (tests/unit/public/test_luau_highlight.py checks this with hostile and random input, and that its corpus
    runs every line of this scanner), so nothing is lost or invented. The input is always Roxy's own files (the
    guide and the home examples), never a visitor's text, but the escaping does not rely on that.

What to read next
    `roxy/public/pages.py` (where guide fences and the home examples are highlighted), then the "Luau highlighting"
    section of `roxy/static/public/site.css` (the colors, checked by `scripts/check_contrast.py --public`).
"""

from __future__ import annotations

import html
import re
import string
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from markupsafe import Markup


class Kind(StrEnum):
    """What a token is. `PLAIN` (names, punctuation, whitespace) is written without a span."""

    PLAIN = "plain"
    KEYWORD = "keyword"  # also attributes such as `@native`
    STRING = "string"
    NUMBER = "number"
    COMMENT = "comment"
    BUILTIN = "builtin"
    TYPE = "type"
    OPERATOR = "operator"
    INTERPOLATION = "interpolation"  # the `{` and `}` around an expression inside a backtick string


CSS_CLASS: Final[dict[Kind, str]] = {
    Kind.KEYWORD: "k",
    Kind.STRING: "s",
    Kind.NUMBER: "n",
    Kind.COMMENT: "c",
    Kind.BUILTIN: "b",
    Kind.TYPE: "t",
    Kind.OPERATOR: "o",
    Kind.INTERPOLATION: "i",
}
"""One letter per kind: the guide has hundreds of spans, and each class name is repeated in every one."""

SCOPE_CLASS: Final = "hl"
"""Class of the `<code>` element around highlighted code; site.css colors `.hl .k` and friends only there."""

MAX_NESTING: Final = 16
"""Deepest nesting scanned as structure: backtick strings inside interpolations, `typeof(...)` and brackets
inside types. Real code stays far below it; deeper text is scanned flat, so a hostile input can never exhaust
Python's recursion limit."""


@dataclass(frozen=True, slots=True)
class Token:
    """One piece of the source: what it is and its exact text."""

    kind: Kind
    text: str


# --- vocabulary ---------------------------------------------------------------------------------------------------

KEYWORDS: Final = frozenset(
    {
        "and",
        "break",
        "do",
        "else",
        "elseif",
        "end",
        "false",
        "for",
        "function",
        "if",
        "in",
        "local",
        "nil",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "true",
        "until",
        "while",
        "typeof",  # a built-in function, but also usable in types (`typeof(value)`); shown as a keyword
    }
)
"""Reserved words (Lua 5.1's, which Luau keeps) plus `typeof`."""

CONTEXTUAL_KEYWORDS: Final = frozenset({"continue", "type", "export", "const"})
"""Luau keywords that are not reserved: each is a keyword only where `contextual_keyword` says so."""

_EXPRESSION_WORDS: Final = frozenset({"and", "or", "then", "do", "in"})
"""Words that continue an expression: `continue` followed by one of them is a variable, not the statement."""

LIBRARIES: Final = frozenset(
    {"bit32", "buffer", "coroutine", "debug", "math", "os", "string", "table", "task", "utf8", "vector"}
)
"""Built-in libraries: `string.lower` is shown as one built-in piece."""

BUILTIN_GLOBALS: Final = LIBRARIES | frozenset(
    {
        # Luau
        "assert",
        "error",
        "gcinfo",
        "getfenv",
        "getmetatable",
        "ipairs",
        "newproxy",
        "next",
        "pairs",
        "pcall",
        "print",
        "rawequal",
        "rawget",
        "rawlen",
        "rawset",
        "require",
        "select",
        "setfenv",
        "setmetatable",
        "tonumber",
        "tostring",
        "unpack",
        "xpcall",
        "_G",
        "_VERSION",
        # Roblox
        "game",
        "workspace",
        "script",
        "plugin",
        "shared",
        "warn",
        "tick",
        "time",
        "elapsedTime",
        "wait",
        "delay",
        "spawn",
        "Enum",
        "Instance",
        "Random",
        "DateTime",
        "Vector2",
        "Vector3",
        "CFrame",
        "Color3",
        "BrickColor",
        "UDim",
        "UDim2",
        "TweenInfo",
        # Services, as scripts usually name them
        "HttpService",
        "Players",
        "ReplicatedStorage",
        "RunService",
        "ServerScriptService",
        "ServerStorage",
        "MessagingService",
        "MemoryStoreService",
        "DataStoreService",
    }
)
"""Global names shown as built-ins when they are not a field of something else (`x.game` is plain)."""

BUILTIN_METHODS: Final = frozenset(
    {
        "GetService",
        "FindFirstChild",
        "WaitForChild",
        "GetAsync",
        "PostAsync",
        "RequestAsync",
        "JSONDecode",
        "JSONEncode",
        "UrlEncode",
        "GenerateGUID",
        "GetSecret",
        "Connect",
        "Once",
        "Wait",
        "Destroy",
        "Clone",
        "IsA",
        "GetChildren",
        "GetDescendants",
    }
)
"""Roblox methods shown as built-ins after `:` or `.` (`HttpService:RequestAsync`, `HttpService.GetAsync`)."""

# Longest first, so `..=` wins over `..` and `.`, `//=` over `//` and `/`, and `->` over `-`.
OPERATORS: Final = (
    "...",
    "..=",
    "//=",
    "::",
    "->",
    "==",
    "~=",
    "<=",
    ">=",
    "..",
    "//",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "^=",
    "+",
    "-",
    "*",
    "/",
    "%",
    "^",
    "#",
    "=",
    "<",
    ">",
    "?",
    "|",
    "&",
)

# Luau names are ASCII: a letter or `_`, then letters, digits and `_` (str.isalnum would also accept other scripts).
_NAME_START: Final = frozenset(string.ascii_letters + "_")
_NAME_CHARS: Final = _NAME_START | frozenset(string.digits)
_DIGITS: Final = frozenset(string.digits)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER = re.compile(
    r"0[xX][0-9A-Fa-f_]*"  # hexadecimal: 0xFF, 0x7FFF_FFFF
    r"|0[bB][01_]*"  # binary: 0b1010_0101
    r"|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9_]*)?"  # 1, 1_000, 1.5, .5, 2e10
)
_LONG_OPEN = re.compile(r"\[(=*)\[")  # `[[` or `[==[`: the opening of a long string or long comment
_SPACE = re.compile(r"[ \t\r\n\f\v]+")
_INLINE_SPACE = re.compile(r"[ \t]*")
_TYPE_PREFIX_WORDS: Final = frozenset({"read", "write"})
"""Property modifiers inside table types (`{ read name: string }`); plain words there, never type names."""


# --- the scanner --------------------------------------------------------------------------------------------------


class _Scanner:
    """Cuts one source text into tokens. Every step consumes at least one character, so it always ends."""

    def __init__(self, source: str) -> None:
        self.src = source
        self.pos = 0
        self.end = len(source)
        self.tokens: list[Token] = []
        self.depth = 0  # open nesting levels (backtick strings, typeof(...), type brackets), at most MAX_NESTING
        self.last = ""  # text of the last token that was not whitespace or a comment

    # Low-level helpers.

    def emit(self, kind: Kind, end: int) -> None:
        """Turn `src[pos:end]` into one token and move past it (nothing when the range is empty)."""
        if end <= self.pos:
            return
        text = self.src[self.pos : end]
        self.tokens.append(Token(kind, text))
        self.pos = end
        if kind is not Kind.COMMENT and not text.isspace():
            self.last = text

    def peek_char(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.src[index] if index < self.end else ""

    def name_at(self, index: int) -> str:
        match = _NAME.match(self.src, index)
        return match.group(0) if match else ""

    def skip_inline_space(self, start: int) -> int:
        """The index of the first character at or after `start` that is not a space or a tab."""
        match = _INLINE_SPACE.match(self.src, start)
        return match.end() if match else start

    @contextmanager
    def nested(self) -> Iterator[bool]:
        """Open one nesting level for the `with` body. Yields False (opening nothing) when `MAX_NESTING` levels are
        already open; the caller then leaves the rest to the flat scanning around it."""
        if self.depth >= MAX_NESTING:
            yield False
            return
        self.depth += 1
        try:
            yield True
        finally:
            self.depth -= 1

    # Whitespace and comments: one definition of where each ends, used to emit them and to look past them.

    def comment_end(self, index: int) -> int:
        """Where the comment starting at `index` ends, or `index` itself when no comment starts there."""
        if not self.src.startswith("--", index):
            return index
        long_open = _LONG_OPEN.match(self.src, index + 2)
        if long_open:
            closing = f"]{long_open.group(1)}]"
            close = self.src.find(closing, long_open.end())
            return self.end if close < 0 else close + len(closing)
        newline = self.src.find("\n", index)
        return self.end if newline < 0 else newline  # the line break itself is whitespace, not comment

    def space_or_comment_end(self, index: int) -> int:
        """The end of the whitespace run or the one comment at `index` (`index` itself when there is neither)."""
        space = _SPACE.match(self.src, index)
        return space.end() if space else self.comment_end(index)

    def next_significant(self, index: int) -> int:
        """The index of the next character at or after `index` that is not whitespace or in a comment."""
        while (after := self.space_or_comment_end(index)) > index:
            index = after
        return index

    def scan_space_or_comment(self) -> bool:
        """Emit whitespace or one comment at `pos`; False when there is neither."""
        end = self.space_or_comment_end(self.pos)
        if end == self.pos:
            return False
        self.emit(Kind.COMMENT if self.src.startswith("--", self.pos) else Kind.PLAIN, end)
        return True

    def skip_to(self, index: int) -> None:
        """Emit the whitespace and comments between `pos` and `index` (found by `next_significant`)."""
        while self.pos < index and self.scan_space_or_comment():
            pass

    # Strings and numbers.

    def escape_end(self, index: int) -> int:
        """The index right after the escape sequence whose backslash is at `index`."""
        escaped = self.src[index + 1 : index + 2]
        if escaped == "z":  # `\z` also skips the spaces and line breaks after it
            space = _SPACE.match(self.src, index + 2)
            return space.end() if space else index + 2
        if escaped == "\r" and self.src.startswith("\n", index + 2):
            return index + 3  # a backslash before a Windows line break continues the string
        return index + 2  # `\"`, `\\`, `\n`, `\{`, or a backslash before a line break (a continuation)

    def quoted_end(self, index: int, quote: str) -> int:
        """Where a quoted string whose text starts at `index` ends: after its closing quote, or before an
        unescaped line break (an unterminated string never swallows the rest of the file)."""
        while index < self.end:
            char = self.src[index]
            if char == "\\":
                index = self.escape_end(index)
            elif char == quote:
                return index + 1
            elif char == "\n":
                return index
            else:
                index += 1
        return self.end

    def scan_string(self) -> bool:
        """Emit a quoted string, a long bracket string or a backtick string at `pos`; False when there is none."""
        char = self.peek_char()
        if char in ('"', "'"):
            self.emit(Kind.STRING, self.quoted_end(self.pos + 1, char))
            return True
        if char == "`":
            self.scan_interpolated()
            return True
        long_open = _LONG_OPEN.match(self.src, self.pos)
        if long_open is None:
            return False
        closing = f"]{long_open.group(1)}]"
        close = self.src.find(closing, long_open.end())
        self.emit(Kind.STRING, self.end if close < 0 else close + len(closing))
        return True

    def scan_interpolated(self) -> None:
        """A backtick string: text parts are STRING, each `{expression}` is scanned as code between two
        INTERPOLATION braces. `\\{` and `` \\` `` are escapes, and the string ends at a line break.

        `pos` stays at the start of the current text part while `index` looks ahead, so each part is emitted whole.
        """
        index = self.pos + 1
        while index < self.end:
            char = self.src[index]
            if char == "\\":
                index = self.escape_end(index)
            elif char == "`":
                self.emit(Kind.STRING, index + 1)
                return
            elif char == "\n":
                break
            elif char == "{":
                with self.nested() as entered:
                    if entered:
                        self.emit(Kind.STRING, index)  # the text before the brace (nothing for `}{`)
                        self.emit(Kind.INTERPOLATION, index + 1)
                        self.scan_code(stop="}")
                if not entered:
                    index += 1  # too deep: the brace stays string text
                    continue
                if self.peek_char() != "}":
                    return  # the text ended inside the expression
                self.emit(Kind.INTERPOLATION, self.pos + 1)
                index = self.pos  # back in the string text, which starts a new part here
            else:
                index += 1
        self.emit(Kind.STRING, min(index, self.end))

    def scan_number(self) -> bool:
        if not (self.peek_char() in _DIGITS or (self.peek_char() == "." and self.peek_char(1) in _DIGITS)):
            return False
        match = _NUMBER.match(self.src, self.pos)  # always matches here: a digit, or a dot and a digit
        self.emit(Kind.NUMBER, match.end() if match else self.pos + 1)
        return True

    def scan_operator(self) -> str:
        """Emit the longest operator at `pos` and return it, or return "" when there is none."""
        for operator in OPERATORS:
            if self.src.startswith(operator, self.pos):
                self.emit(Kind.OPERATOR, self.pos + len(operator))
                return operator
        return ""

    # Code (values and statements).

    def scan_code(self, stop: str | None = None) -> None:
        """Scan code until the end, or until an unmatched closing `stop` bracket (left unconsumed)."""
        brackets = 0
        while self.pos < self.end:
            char = self.src[self.pos]
            if char == stop and brackets == 0:
                return
            if self.scan_space_or_comment() or self.scan_string() or self.scan_number():
                continue
            if char in _NAME_START:
                self.scan_name()
            elif char == ":" and not self.src.startswith("::", self.pos):
                self.scan_colon()
            elif char == "<" and self.opens_generics():
                self.emit(Kind.OPERATOR, self.pos + 1)  # generic parameters: `function f<T>(x: T): T`
                self.scan_type_list(closing=">")
            elif char == "@" and self.name_at(self.pos + 1):
                self.emit(Kind.KEYWORD, self.pos + 1 + len(self.name_at(self.pos + 1)))  # an attribute: `@native`
            elif (operator := self.scan_operator()) == "::":
                self.scan_type()  # a cast: `value :: Type`
            elif not operator:
                if char in "([{":
                    brackets += 1
                elif char in ")]}":
                    brackets = max(0, brackets - 1)
                self.emit(Kind.PLAIN, self.pos + 1)  # punctuation, or any character Luau does not know

    def opens_generics(self) -> bool:
        """Does the `<` at `pos` open generic parameters? It does right after `function` (an anonymous function)
        and right after `function name` (also `function a.b:c`); anywhere else `<` compares.

        Looks back over the name and the spaces before it without copying text, so a file full of `<` stays
        linear time.
        """
        if self.last == "function":
            return True
        index = self.pos
        while index > 0 and (self.src[index - 1] in _NAME_CHARS or self.src[index - 1] in ".:"):
            index -= 1
        if index == self.pos or self.src[index] not in _NAME_START:
            return False  # no name right before `<` (a number, a field access with nothing before it, or nothing)
        while index > 0 and self.src[index - 1] in " \t":
            index -= 1
        start = index - len("function")
        before_ok = start == 0 or (start > 0 and self.src[start - 1] not in _NAME_CHARS)
        return before_ok and self.src.startswith("function", start)

    def scan_name(self) -> None:
        name = self.name_at(self.pos)
        end = self.pos + len(name)
        if self.last == ".":  # a field (or a method called with `.`): `x.game` is not the global `game`
            self.emit(Kind.BUILTIN if name in BUILTIN_METHODS else Kind.PLAIN, end)
        elif name in KEYWORDS:
            self.emit(Kind.KEYWORD, end)
            if name == "typeof" and self.peek_char() == "(":
                self.scan_typeof_argument()
        elif name in CONTEXTUAL_KEYWORDS and self.contextual_keyword(name, end):
            self.emit(Kind.KEYWORD, end)
            if name == "type":
                self.scan_type_alias()
        elif name in LIBRARIES and self.src.startswith(".", end) and self.name_at(end + 1):
            self.emit(Kind.BUILTIN, end + 1 + len(self.name_at(end + 1)))  # `string.lower` as one piece
        elif name in BUILTIN_GLOBALS or (name == "type" and self.src.startswith("(", self.skip_inline_space(end))):
            self.emit(Kind.BUILTIN, end)  # `type(value)` is the built-in function
        else:
            self.emit(Kind.PLAIN, end)

    def contextual_keyword(self, name: str, end: int) -> bool:
        """Is this `continue`, `type`, `export` or `const` used as a keyword here, or as an ordinary name?"""
        if name == "continue":
            # A statement of its own: nothing, `;` or the next statement follows (`end`, `local`, a name...),
            # never an operator, a call, an index or a word that continues an expression (`and`, `then`...).
            following = self.next_significant(end)
            if following >= self.end or self.src[following] == ";":
                return True
            next_name = self.name_at(following)
            return bool(next_name) and next_name not in _EXPRESSION_WORDS
        same_line = self.skip_inline_space(end)
        next_name = self.name_at(same_line) if same_line > end else ""
        if name == "export":
            return next_name == "type"
        # `type Name = ...`, `type function name`, `const name = ...` and `const function name`: a name (not a
        # reserved word, except `function`) on the same line. `type(x)`, `const = 1` and `type then` are names.
        return bool(next_name) and (next_name not in KEYWORDS or next_name == "function")

    def scan_colon(self) -> None:
        """`obj:method(...)` is a method call; any other single `:` starts a type annotation (also `x: typeof(y)`,
        which looks like a call of a method named `typeof`)."""
        after = self.skip_inline_space(self.pos + 1)
        method = self.name_at(after)
        call = self.skip_inline_space(after + len(method))
        is_call = method not in ("", "typeof") and call < self.end and self.src[call] in "(\"'{`["
        self.emit(Kind.PLAIN, self.pos + 1)
        if is_call:
            self.skip_to(after)
            self.emit(Kind.BUILTIN if method in BUILTIN_METHODS else Kind.PLAIN, after + len(method))
        else:
            self.scan_type()

    def scan_typeof_argument(self) -> None:
        """The `(expression)` after `typeof`, scanned as code (bounded nesting)."""
        self.emit(Kind.PLAIN, self.pos + 1)
        with self.nested() as entered:
            if entered:
                self.scan_code(stop=")")
        if entered and self.peek_char() == ")":
            self.emit(Kind.PLAIN, self.pos + 1)

    def scan_type_alias(self) -> None:
        """After the keyword `type`: `Name<T...> = type` (or `function name`, a type function: plain code)."""
        self.skip_to(self.next_significant(self.pos))
        if self.name_at(self.pos) == "function":
            return  # `type function f(...)`: the body is ordinary code
        self.scan_type()  # the alias name and its generic parameters, up to `=`
        equals = self.next_significant(self.pos)
        if self.src.startswith("=", equals) and not self.src.startswith("==", equals):
            self.skip_to(equals)
            self.emit(Kind.OPERATOR, equals + 1)
            self.scan_type()

    # Types.

    def scan_type(self) -> None:
        """Scan one type expression, stopping before the first token that cannot continue it."""
        expect_operand = True
        while True:
            following = self.next_significant(self.pos)
            if following >= self.end or not (expect_operand or self.continues_type(following)):
                return
            self.skip_to(following)  # whitespace and comments inside the type
            char = self.src[self.pos]
            if expect_operand:
                if char in "|&":
                    self.emit(Kind.OPERATOR, self.pos + 1)  # a leading `|` or `&`: `type T = | "a" | "b"`
                elif self.scan_type_operand():
                    expect_operand = False
                else:
                    return
            elif char == "?" or self.src.startswith("...", self.pos):
                self.emit(Kind.OPERATOR, self.pos + (1 if char == "?" else 3))  # optional `T?`, generic pack `T...`
            elif char == "<":
                self.emit(Kind.OPERATOR, self.pos + 1)
                self.scan_type_list(closing=">")
            elif char == ".":
                self.emit(Kind.PLAIN, self.pos + 1)  # `Module.Type`
                expect_operand = True
            else:  # `|`, `&` or `->`: another operand follows
                self.scan_operator()
                expect_operand = True

    def continues_type(self, index: int) -> bool:
        """After a complete type, does the token at `index` continue it?"""
        char = self.src[index]
        if char in "?|&" or self.src.startswith("->", index):
            return True  # none of these can follow a value in code, so they always belong to the type
        touching = index == self.pos  # `Module.Type`, `T...` and `Array<T>` have no space before the `.` or `<`
        if char == ".":
            return touching and (self.src.startswith("...", index) or bool(self.name_at(index + 1)))
        return char == "<" and touching and _NAME.fullmatch(self.last) is not None

    def scan_type_operand(self) -> bool:
        """One type without its operators: a name, a table type, a function or tuple type, a string singleton,
        `typeof(...)`, `...T`. False when the next token cannot start a type (the type ends there)."""
        char = self.peek_char()
        name = self.name_at(self.pos)
        if name == "function":
            return False  # `function` starts code, never a type
        if name in ("nil", "true", "false", "typeof"):
            self.emit(Kind.KEYWORD, self.pos + len(name))
            if name == "typeof" and self.peek_char() == "(":
                self.scan_typeof_argument()
        elif name:
            self.emit(Kind.TYPE, self.pos + len(name))
        elif char in "{(":
            self.emit(Kind.PLAIN, self.pos + 1)
            self.scan_type_list(closing="}" if char == "{" else ")")
        elif char == "<":  # a generic function type: `<T>(T) -> T`, generics first, then the parameters
            self.emit(Kind.OPERATOR, self.pos + 1)
            self.scan_type_list(closing=">")
            parameters = self.next_significant(self.pos)
            if self.src.startswith("(", parameters):
                self.skip_to(parameters)
                self.emit(Kind.PLAIN, parameters + 1)
                self.scan_type_list(closing=")")
        elif char in ('"', "'"):
            self.emit(Kind.STRING, self.quoted_end(self.pos + 1, char))
        elif self.src.startswith("...", self.pos):
            self.emit(Kind.OPERATOR, self.pos + 3)  # a variadic `...number`: the type name follows directly
            name = self.name_at(self.pos)
            if name and name != "function":
                self.emit(Kind.TYPE, self.pos + len(name))
        else:
            return False
        return True

    def scan_type_list(self, closing: str) -> None:
        """The inside of `{...}`, `(...)`, `[...]` or `<...>` in a type, up to and including `closing`.

        Holds types separated by `,` or `;`, where a `name:` (or `[key]:`) in front of a type labels a field or
        parameter, and `=` gives a default in a generic list. Stops early at anything else, so broken input
        falls back to ordinary code scanning. One nesting level deeper; past `MAX_NESTING` the inside is left to
        the code scanner.
        """
        with self.nested() as entered:
            while entered:
                self.skip_to(self.next_significant(self.pos))
                if self.pos >= self.end:
                    return
                char = self.src[self.pos]
                if char == closing:
                    self.emit(Kind.OPERATOR if closing == ">" else Kind.PLAIN, self.pos + 1)
                    return
                if char in ",;":
                    self.emit(Kind.PLAIN, self.pos + 1)
                elif char == "=" and closing == ">":
                    self.emit(Kind.OPERATOR, self.pos + 1)  # a default: `<T = string>`
                elif char == "[" and closing == "}":  # an indexer: `[string]: number`
                    self.emit(Kind.PLAIN, self.pos + 1)
                    self.scan_type_list(closing="]")
                    self.scan_field_colon()
                elif label_end := self.field_label():
                    self.emit(Kind.PLAIN, label_end)  # `name` (and a `read` or `write` before it)
                    self.scan_field_colon()
                else:
                    before = self.pos
                    self.scan_type()
                    if self.pos == before:
                        return  # not a type: leave it to the code scanner

    def field_label(self) -> int:
        """If a field or parameter label (`name:` or `read name:`) starts at `pos`, the index where its words end;
        else 0."""
        name = self.name_at(self.pos)
        end = self.pos + len(name)
        if name in _TYPE_PREFIX_WORDS:
            second_start = self.skip_inline_space(end)
            second = self.name_at(second_start)
            if second and second_start > end:
                end = second_start + len(second)  # `read name`
        colon = self.skip_inline_space(end)
        is_label = bool(name) and self.src.startswith(":", colon) and not self.src.startswith("::", colon)
        return end if is_label else 0

    def scan_field_colon(self) -> None:
        """The `:` after a field label or an indexer, then the field's type."""
        colon = self.next_significant(self.pos)
        if self.src.startswith(":", colon) and not self.src.startswith("::", colon):
            self.skip_to(colon)
            self.emit(Kind.PLAIN, colon + 1)
            self.scan_type()


# --- public API ---------------------------------------------------------------------------------------------------


def tokenize(source: str) -> list[Token]:
    """Cut Luau source into tokens whose texts join back to exactly `source`. Never raises for any text."""
    scanner = _Scanner(source)
    scanner.scan_code()
    return scanner.tokens


def highlight(source: str) -> Markup:
    """Luau source as escaped HTML with a `<span class="...">` around each highlighted token.

    Neighboring tokens of the same kind share one span (with any whitespace between them), which keeps the page
    small: `end\\n\\tend` is one keyword span. The caller wraps the result in `<code class="hl">`.
    """
    out: list[str] = []
    open_kind: Kind | None = None
    pending_space = ""  # whitespace seen after an open span, written once we know whether the span continues
    for token in tokenize(source):
        if token.kind is Kind.PLAIN and token.text.isspace() and open_kind is not None:
            pending_space += token.text
            continue
        if token.kind is open_kind:
            out.append(html.escape(pending_space + token.text, quote=False))
            pending_space = ""
            continue
        if open_kind is not None:
            out.append("</span>")
            open_kind = None
        if pending_space:
            out.append(html.escape(pending_space, quote=False))
            pending_space = ""
        if token.kind is Kind.PLAIN:
            out.append(html.escape(token.text, quote=False))
        else:
            out.append(f'<span class="{CSS_CLASS[token.kind]}">{html.escape(token.text, quote=False)}')
            open_kind = token.kind
    if open_kind is not None:
        out.append("</span>")
    out.append(html.escape(pending_space, quote=False))
    return Markup("".join(out))  # noqa: S704 (every text piece is escaped above; class names are constants)
