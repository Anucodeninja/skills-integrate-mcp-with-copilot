import getpass
import json
import os
from pathlib import Path

from app import hash_teacher_password


def main():
    username = input("Teacher username: ").strip()
    if not username or any(character.isspace() for character in username):
        raise SystemExit("Username must be non-empty and contain no spaces.")

    password = getpass.getpass("Teacher password (at least 12 characters): ")
    confirmation = getpass.getpass("Confirm teacher password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")

    accounts_file = Path(os.environ.get(
        "TEACHER_ACCOUNTS_FILE", Path(__file__).with_name("teachers.json")
    ))
    try:
        data = json.loads(accounts_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {"teachers": []}
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Cannot read teacher accounts: {error}") from error

    teachers = data.get("teachers") if isinstance(data, dict) else None
    if not isinstance(teachers, list):
        raise SystemExit("Teacher account file must contain a teachers list.")
    if any(
        isinstance(teacher, dict)
        and isinstance(teacher.get("username"), str)
        and teacher.get("username", "").casefold() == username.casefold()
        for teacher in teachers
    ):
        raise SystemExit("That teacher username already exists.")

    teachers.append({"username": username, **hash_teacher_password(password)})
    accounts_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    accounts_file.chmod(0o600)
    print(f"Added teacher account '{username}' to {accounts_file}.")


if __name__ == "__main__":
    main()