"""Run ABE setup() once and write pk.bin / msk.enc (doc 02 Section 4.1, doc 03 Section 5)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.key_authority import msk_path, pk_path, setup_and_save  # noqa: E402


def main() -> None:
    setup_and_save()
    print("Wrote", pk_path())
    print("Wrote", msk_path())


if __name__ == "__main__":
    main()
