import os
import tempfile

FILES = list()
# Env override lets tests/dev point at a sandbox instead of /etc/roxy.
ROXY_FILE_ROOT = os.environ.get("ROXY_FILE_ROOT", "/etc/roxy/")
with open(os.path.join(ROXY_FILE_ROOT, "files.txt"), "r") as file:
    lines = file.read().strip().splitlines()
    for file_name in lines:
        FILES.append(os.path.join(ROXY_FILE_ROOT, file_name))

if len(FILES) < 4:
    raise RuntimeError(f"files.txt must list 4 files (credentials, app password, tokens, emails); found {len(FILES)}")


def read_admin_credentials() -> list[str]:
    with open(FILES[0], "r") as file:
        credentials = file.read().strip().splitlines()
    if len(credentials) < 4:
        raise RuntimeError("The credentials file must have 4 lines: username, password, HMAC key, session secret")
    return credentials


def read_app_password() -> str:
    with open(FILES[1], "r") as file:
        return file.read().strip()


def read_tokens() -> list[str]:
    with open(FILES[2], "r") as file:
        return file.read().strip().splitlines()


def write_tokens(tokens: list[str]) -> bool:
    """Atomically replace the token file so the set survives a restart. Returns True on success."""
    tmp_path = None
    try:
        directory = os.path.dirname(FILES[2]) or "."
        # mkstemp creates the file 0600, matching the expected /etc/roxy permissions.
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tokens_", suffix=".tmp")
        with os.fdopen(fd, "w") as file:
            file.write("\n".join(tokens) + "\n")
        os.replace(tmp_path, FILES[2])
        return True
    except OSError:
        if tmp_path is not None:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        return False


def get_emails() -> tuple[str, str]:
    with open(FILES[3], "r") as file:
        main, alt, *_ = file.read().strip().splitlines()
        return main, alt


def read_rotate_proxy() -> str:
    """The IP-rotation proxy URL, or "" if rotation isn't configured.

    Precedence: ROXY_ROTATE_PROXY env var, then the rotate_proxy.txt file. Both
    are optional, so existing deploys keep working with rotation simply disabled.
    """
    import config

    if config.ROTATE_PROXY_ENV.strip():
        return config.ROTATE_PROXY_ENV.strip()
    try:
        with open(config.ROTATE_PROXY_FILE, "r") as file:
            return file.read().strip()
    except OSError:
        return ""


def rotate_proxy_mtime() -> float:
    import config

    try:
        return os.path.getmtime(config.ROTATE_PROXY_FILE)
    except OSError:
        return 0.0


def tokens_mtime() -> float:
    """Last-modified time of the token file (so workers can reload it on change)."""
    try:
        return os.path.getmtime(FILES[2])
    except OSError:
        return 0.0
