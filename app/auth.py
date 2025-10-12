FILES = list()
ROXY_FILE_ROOT = "/etc/roxy/"
with open(f"{ROXY_FILE_ROOT}files.txt", "r") as file:
    lines = file.read().strip().splitlines()
    for file_name in lines:
        FILES.append(f"{ROXY_FILE_ROOT}{file_name}")


def read_admin_credentials() -> list[str]:
    with open(FILES[0], "r") as file:
        return file.read().strip().splitlines()


def read_app_password() -> str:
    with open(FILES[1], "r") as file:
        return file.read().strip()


def read_tokens() -> list[str]:
    with open(FILES[2], "r") as file:
        return file.read().strip().splitlines()


def get_emails() -> tuple[str, str]:
    with open(FILES[3], "r") as file:
        main, alt, *_ = file.read().strip().splitlines()
        return main, alt
