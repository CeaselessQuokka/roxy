def read_tokens() -> list[str]:
    with open("/etc/auth_tokens.txt", "r") as file:
        return file.read().strip().splitlines()


def read_admin_credentials() -> list[str]:
    with open("/etc/admin_credentials.txt", "r") as file:
        return file.read().strip().splitlines()


def read_app_password() -> str:
    with open("/etc/app_password.txt", "r") as file:
        return file.read().strip()
