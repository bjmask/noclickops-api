from pathlib import Path
import re

FILE = Path("gcp/testable-permissions")
KEYWORDS = ("get", "list", "create", "delete" ,"update")

def main():
    if not FILE.exists():
        raise SystemExit(f"Missing file: {FILE}")
    pattern = re.compile("|".join(KEYWORDS), re.IGNORECASE)

    with FILE.open() as f:
        for line in f:
            perm = line.strip()
            if not perm:
                continue
            last = perm.split(".")[-1]
            if not pattern.search(last):
                print(f"{perm} => {last}")

if __name__ == "__main__":
    main()
