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
    rendered once per file version and the home examples once per process. It also works without JavaScript and
    keeps the markup small: one-letter class names whose colors live in site.css, for both themes.

How it works
    A hand-written scanner reads the text left to right, one token at a time (a "lexer"). Most tokens can be
    recognized on their own: comments (`-- line` and long `--[[ ]]` or `--[==[ ]==]` comments), strings (quoted,
    long brackets `[[ ]]` and `[=[ ]=]`, and backtick strings whose `{expression}` parts are scanned again as
    code), numbers (decimal, hex `0xFF`, binary `0b1010`, `_` separators, exponents), names and operators.
    Three things need a little context, which the scanner keeps:
    - Contextual keywords. Luau added `continue`, `type`, `export` and `const` without reserving them, so a script
      may still use them as names. `type Foo = ...` is a declaration but `type(value)` is the built-in function;
      `continue` is a keyword only where a statement follows. Each rule looks at the next token to decide.
    - Types. Luau annotations reuse `:`, which also calls methods (`HttpService:GetAsync(url)`). A `:` followed by
      a name and then `(`, a string or `{` is a method call; any other `:` starts a type annotation. `::` casts,
      `type Name =` aliases and `<T>` after `function` also start types. Inside a type, names are type names
      (`number`, `GameDetails`), `name:` inside braces or parentheses is a field or parameter name, and the type
      ends at the first token that cannot continue it (`=`, a `,` outside brackets, a new statement).
    - Built-ins. Roblox and Luau globals (`game`, `task`, `print`, `pcall`...) when they are not a field of
      something else, library calls as one piece (`string.lower`, `task.wait`), and well-known methods after
      `:` or `.` (`GetService`, `RequestAsync`, `JSONDecode`...).
    Safety: every piece of text goes through `html.escape` before it is written, and class names come only from
    the fixed `CSS_CLASS` table, never from the input. Joining the tokens gives back the input exactly (tests check
    this with hostile and random input), so nothing is lost or invented. Broken input never raises: an
    unterminated string or comment simply runs to the end of the line or the text, and nesting deeper than
    `MAX_NESTING` (backtick strings inside interpolations inside backtick strings...) is kept as string text.

What to read next
    `roxy/public/pages.py` (where guide fences and the home examples are highlighted), then the "Luau highlighting"
    section of `roxy/static/public/site.css` (the colors).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from markupsafe import Markup


class Kind(StrEnum):
    """What a token is. `PLAIN` (names, punctuation, whitespace) is written without a span."""

    PLAIN = "plain"
    KEYWORD = "keyword"
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
"""Deepest nesting of backtick strings and `typeof(...)` scanned as code. Deeper text stays string text, so a
hostile input can never exhaust Python's recursion limit."""


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

# Longest first, so `..=` wins over `..` and `.`, and `//=` over `//` and `/`.
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
        self.depth = 0  # nesting of backtick strings and typeof(...), bounded by MAX_NESTING
        self.last = ""  # text of the last token that was not whitespace or a comment

    # Low-level helpers.

    def emit(self, kind: Kind, end: int) -> None:
        """Turn `src[pos:end]` into one token and move past it."""
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

    def skip_inline_space(self, start: int) -> int:
        """The index of the first character at or after `start` that is not a space or a tab."""
        match = _INLINE_SPACE.match(self.src, start)
        return match.end() if match else start

    def next_significant(self, start: int) -> int:
        """The index of the next character that is not whitespace or inside a comment (or the end)."""
        index = start
        while index < self.end:
            space = _SPACE.match(self.src, index)
            if space:
                index = space.end()
                continue
            if self.src.startswith("--", index):
                long_open = _LONG_OPEN.match(self.src, index + 2)
                if long_open:
                    close = self.src.find(f"]{long_open.group(1)}]", long_open.end())
                    index = self.end if close < 0 else close + len(long_open.group(1)) + 2
                else:
                    newline = self.src.find("\n", index)
                    index = self.end if newline < 0 else newline
                continue
            break
        return index

    def name_at(self, index: int) -> str:
        match = _NAME.match(self.src, index)
        return match.group(0) if match else ""

    def skip_to(self, index: int) -> None:
        """Emit the whitespace and comments between `pos` and `index` (found by `next_significant`)."""
        while self.pos < index and self.scan_space_or_comment():
            pass

    # Tokens that look the same in code and in types.

    def scan_space_or_comment(self) -> bool:
        """Emit whitespace or one comment at `pos`; False when there is neither."""
        space = _SPACE.match(self.src, self.pos)
        if space:
            self.emit(Kind.PLAIN, space.end())
            return True
        if not self.src.startswith("--", self.pos):
            return False
        long_open = _LONG_OPEN.match(self.src, self.pos + 2)
        if long_open:
            closing = f"]{long_open.group(1)}]"
            close = self.src.find(closing, long_open.end())
            self.emit(Kind.COMMENT, self.end if close < 0 else close + len(closing))
        else:
            newline = self.src.find("\n", self.pos)
            self.emit(Kind.COMMENT, self.end if newline < 0 else newline)  # the newline itself is plain
        return True

    def scan_string(self) -> bool:
        """Emit a quoted string, a long bracket string or a backtick string at `pos`; False when there is none."""
        char = self.peek_char()
        if char in ('"', "'"):
            self.emit(Kind.STRING, self.quoted_end(self.pos + 1, char))
            return True
        if char == "[":
            long_open = _LONG_OPEN.match(self.src, self.pos)
            if long_open is None:
                return False
            closing = f"]{long_open.group(1)}]"
            close = self.src.find(closing, long_open.end())
            self.emit(Kind.STRING, self.end if close < 0 else close + len(closing))
            return True
        if char == "`":
            self.scan_interpolated()
            return True
        return False

    def quoted_end(self, index: int, quote: str) -> int:
        """Where a quoted string that started before `index` ends: after its closing quote, or before an
        unescaped line break (an unterminated string never swallows the rest of the file)."""
        while index < self.end:
            char = self.src[index]
            if char == "\\":
                index += 2  # an escape: `\"`, `\\`, `\n`, or a backslash before a line break (a continuation)
            elif char == quote:
                return index + 1
            elif char == "\n":
                return index
            else:
                index += 1
        return self.end

    def scan_interpolated(self) -> None:
        """A backtick string: text parts are STRING, each `{expression}` is scanned as code between two
        INTERPOLATION braces. `\\{` and `` \\` `` are escapes, and the string ends at a line break."""
        start = self.pos
        index = self.pos + 1
        while index < self.end:
            char = self.src[index]
            if char == "\\":
                index += 2
            elif char == "`":
                self.pos = start
                self.emit(Kind.STRING, index + 1)
                return
            elif char == "\n":
                break
            elif char == "{" and self.depth < MAX_NESTING:
                self.pos = start
                self.emit(Kind.STRING, index)
                self.emit(Kind.INTERPOLATION, index + 1)
                self.depth += 1
                try:
                    self.scan_code(stop="}")
                finally:
                    self.depth -= 1
                if self.peek_char() == "}":
                    self.emit(Kind.INTERPOLATION, self.pos + 1)
                start = index = self.pos
                if index >= self.end or self.src[index] == "\n":
                    return
                continue  # back inside the string text
            else:
                index += 1
        self.pos = start
        self.emit(Kind.STRING, min(index, self.end))

    def scan_number(self) -> bool:
        char = self.peek_char()
        if not (char.isdigit() or (char == "." and self.peek_char(1).isdigit())):
            return False
        match = _NUMBER.match(self.src, self.pos)
        self.emit(Kind.NUMBER, match.end() if match and match.end() > self.pos else self.pos + 1)
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
            if stop is not None and char == stop and brackets == 0:
                return
            if self.scan_space_or_comment() or self.scan_string() or self.scan_number():
                continue
            if _NAME.match(char):
                self.scan_name()
                continue
            if char == ":" and not self.src.startswith("::", self.pos):
                self.scan_colon()
                continue
            if char == "<" and (self.last == "function" or self.after_function_name()):
                self.emit(Kind.OPERATOR, self.pos + 1)  # generic parameters: `function f<T>(x: T)`
                self.scan_nested_type_list(closing=">")
                continue
            operator = self.scan_operator()
            if operator == "::":
                self.scan_type()
                continue
            if operator:
                continue
            if char in "([{":
                brackets += 1
            elif char in ")]}":
                brackets = max(0, brackets - 1)
            self.emit(Kind.PLAIN, self.pos + 1)  # punctuation, or any character Luau does not know

    def after_function_name(self) -> bool:
        """True when `pos` follows `function name` (or `function a.b:c`): a `<` there opens generic types.

        Looks back over the name, then over spaces, for the word `function`; never copies the text before it, so
        a long file full of `<` stays linear time.
        """
        index = self.pos - 1
        while index >= 0 and (self.src[index].isalnum() or self.src[index] in "_.:"):
            index -= 1
        if index + 1 >= self.pos or self.src[index + 1] in ".:":
            return False  # no name right before `<`
        while index >= 0 and self.src[index] in " \t":
            index -= 1
        start = index - len("function") + 1
        before_ok = start == 0 or (start > 0 and not (self.src[start - 1].isalnum() or self.src[start - 1] == "_"))
        return start >= 0 and before_ok and self.src.startswith("function", start)

    def scan_name(self) -> None:
        match = _NAME.match(self.src, self.pos)
        assert match is not None  # scan_code checked the first character
        name, end = match.group(0), match.end()
        after_dot = self.last in (".", ":")
        if after_dot:
            self.emit(Kind.BUILTIN if name in BUILTIN_METHODS else Kind.PLAIN, end)
        elif name in KEYWORDS:
            self.emit(Kind.KEYWORD, end)
            if name == "typeof" and self.peek_char() == "(":
                self.scan_typeof_argument()
        elif name in CONTEXTUAL_KEYWORDS and self.contextual_keyword(name, end):
            self.emit(Kind.KEYWORD, end)
            if name == "type":
                self.scan_type_alias()
        elif name in LIBRARIES and self.src.startswith(".", end) and _NAME.match(self.src, end + 1):
            member = _NAME.match(self.src, end + 1)
            assert member is not None
            self.emit(Kind.BUILTIN, member.end())  # `string.lower` as one piece
        elif name in BUILTIN_GLOBALS or (name == "type" and self.src.startswith("(", self.skip_inline_space(end))):
            self.emit(Kind.BUILTIN, end)  # `type(value)` is the built-in function
        else:
            self.emit(Kind.PLAIN, end)

    def contextual_keyword(self, name: str, end: int) -> bool:
        """Is this `continue`, `type`, `export` or `const` used as a keyword here, or as an ordinary name?"""
        following = self.next_significant(end)
        next_name = self.name_at(following) if following < self.end else ""
        if name == "continue":
            # A statement on its own: what follows starts the next statement (`end`, a name), or nothing does.
            return following >= self.end or self.src[following] == ";" or (bool(next_name) and following > end)
        if name == "export":
            return next_name == "type"
        if name == "type":
            # `type Name =` or `type function name`; a following name on the same line, never `type(x)`.
            same_line = self.skip_inline_space(end)
            return same_line > end and bool(self.name_at(same_line))
        # const: `const name` or `const function`
        same_line = self.skip_inline_space(end)
        return same_line > end and bool(self.name_at(same_line))

    def scan_colon(self) -> None:
        """`obj:method(...)` is a method call; any other single `:` starts a type annotation."""
        after = self.skip_inline_space(self.pos + 1)
        method = _NAME.match(self.src, after)
        if method:
            call = self.skip_inline_space(method.end())
            if call < self.end and self.src[call] in "(\"'{`[":
                self.emit(Kind.PLAIN, self.pos + 1)
                return  # the method name is scanned next, after ":"
        self.emit(Kind.PLAIN, self.pos + 1)
        self.scan_type()

    def scan_typeof_argument(self) -> None:
        """The `(expression)` after `typeof`, scanned as code (bounded nesting)."""
        self.emit(Kind.PLAIN, self.pos + 1)
        if self.depth >= MAX_NESTING:
            return
        self.depth += 1
        try:
            self.scan_code(stop=")")
        finally:
            self.depth -= 1
        if self.peek_char() == ")":
            self.emit(Kind.PLAIN, self.pos + 1)

    def scan_type_alias(self) -> None:
        """After the keyword `type`: `Name<T...> = type` (or `function name`, a type function: plain code)."""
        self.scan_space_or_comment()
        if self.name_at(self.pos) == "function":
            return  # `type function f(...)`: the body is ordinary code
        self.scan_type()  # the alias name and its generic parameters, up to `=`
        following = self.next_significant(self.pos)
        if following < self.end and self.src[following] == "=" and not self.src.startswith("==", following):
            while self.pos < following:
                self.scan_space_or_comment()
            self.emit(Kind.OPERATOR, self.pos + 1)
            self.scan_type()

    # Types.

    def scan_type(self) -> None:
        """Scan one type expression, stopping before the first token that cannot continue it."""
        expect_operand = True
        while self.pos < self.end:
            following = self.next_significant(self.pos)
            if following >= self.end:
                return
            char = self.src[following]
            if not expect_operand and not self.continues_type(following):
                return
            while self.pos < following:  # whitespace and comments inside the type
                self.scan_space_or_comment()
            if expect_operand:
                if not self.scan_type_operand():
                    return
                expect_operand = False
            elif char == "?":
                self.emit(Kind.OPERATOR, self.pos + 1)
            elif char == "<":
                self.emit(Kind.OPERATOR, self.pos + 1)
                self.scan_type_list(closing=">")
            elif char == ".":
                if self.src.startswith("...", self.pos):
                    self.emit(Kind.OPERATOR, self.pos + 3)  # a generic pack: `T...`
                else:
                    self.emit(Kind.PLAIN, self.pos + 1)  # `Module.Type`
                    expect_operand = True
            else:  # `|`, `&` or `->`: another operand follows
                self.scan_operator()
                expect_operand = True

    def continues_type(self, index: int) -> bool:
        """After a complete type, does the token at `index` continue it?"""
        if self.src.startswith("->", index):
            return True
        char = self.src[index]
        if char in "?|&":
            return True
        if char == "." and (index == self.pos or self.src[index - 1] not in " \t\r\n"):
            return self.src.startswith("...", index) or bool(self.name_at(index + 1))
        return char == "<" and index == self.pos and bool(self.last) and _NAME.fullmatch(self.last) is not None

    def scan_type_operand(self) -> bool:
        """One type without its operators: a name, a table type, a function or tuple type, a string singleton,
        `typeof(...)`, `...T`. False when the next token cannot start a type (the type ends there)."""
        char = self.peek_char()
        name = self.name_at(self.pos)
        if name:
            end = self.pos + len(name)
            if name in ("nil", "true", "false"):
                self.emit(Kind.KEYWORD, end)
            elif name == "typeof":
                self.emit(Kind.KEYWORD, end)
                if self.peek_char() == "(":
                    self.scan_typeof_argument()
            elif name == "function":
                return False
            else:
                self.emit(Kind.TYPE, end)
            return True
        if char in "{(":
            self.emit(Kind.PLAIN, self.pos + 1)
            self.scan_type_list(closing="}" if char == "{" else ")")
            return True
        if char == "<":  # a generic function type: `<T>(T) -> T`
            self.emit(Kind.OPERATOR, self.pos + 1)
            self.scan_type_list(closing=">")
            return True
        if char in ('"', "'"):
            self.emit(Kind.STRING, self.quoted_end(self.pos + 1, char))
            return True
        if self.src.startswith("...", self.pos):
            self.emit(Kind.OPERATOR, self.pos + 3)
            return True
        return False

    def scan_type_list(self, closing: str) -> None:
        """The inside of `{...}`, `(...)`, `[...]` or `<...>` in a type, up to and including `closing`.

        Holds types separated by `,` or `;`, where a `name:` (or `[key]:`) in front of a type labels a field or
        parameter, and `=` gives a default in a generic list. Stops early at anything else, so broken input
        falls back to ordinary code scanning.
        """
        while self.pos < self.end:
            following = self.next_significant(self.pos)
            while self.pos < following:
                self.scan_space_or_comment()
            if self.pos >= self.end:
                return
            char = self.src[self.pos]
            if char == closing:
                self.emit(Kind.OPERATOR if closing == ">" else Kind.PLAIN, self.pos + 1)
                return
            if char in ",;":
                self.emit(Kind.PLAIN, self.pos + 1)
                continue
            if char == "=" and closing == ">":
                self.emit(Kind.OPERATOR, self.pos + 1)
                continue
            if char == "[" and closing == "}":  # an indexer: `[string]: number`
                self.emit(Kind.PLAIN, self.pos + 1)
                self.scan_type_list(closing="]")
                self.scan_field_colon()
                continue
            label = self.field_label()
            if label:
                self.emit(Kind.PLAIN, label)  # `name` (and a `read` or `write` before it)
                self.scan_field_colon()
                continue
            before = self.pos
            self.scan_type()
            if self.pos == before:
                return  # not a type: leave it to the code scanner

    def field_label(self) -> int:
        """If a field or parameter label (`name:`, `read name:`) starts at `pos`, where it ends; else 0."""
        name = self.name_at(self.pos)
        if not name:
            return 0
        end = self.pos + len(name)
        if name in _TYPE_PREFIX_WORDS:
            after = self.skip_inline_space(end)
            second = self.name_at(after)
            if second and self.src.startswith(":", self.skip_inline_space(after + len(second))):
                end = after + len(second)
        colon = self.skip_inline_space(end)
        if self.src.startswith(":", colon) and not self.src.startswith("::", colon):
            return end
        return 0

    def scan_field_colon(self) -> None:
        """The `:` after a field label or an indexer, then the field's type."""
        following = self.next_significant(self.pos)
        if following < self.end and self.src[following] == ":" and not self.src.startswith("::", following):
            while self.pos < following:
                self.scan_space_or_comment()
            self.emit(Kind.PLAIN, self.pos + 1)
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
