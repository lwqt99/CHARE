"""Verify the CHARE artifact or compare regenerated figure data."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent


def check_manifest():
    entries = (ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    for entry in entries:
        digest, name = entry.split("  ", 1)
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError(f"Invalid manifest path: {name}")
        actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"SHA-256 mismatch: {name}")
    if not entries:
        raise ValueError("Empty SHA256SUMS")
    print(f"PASS {len(entries)} SHA-256 entries")


def check_figures(directory):
    for generated, expected, description in (
        ("plotted_values.csv", "expected_plot_points.csv", "48 plot points"),
        ("service_bytes.csv", "expected_service_bytes.csv", "18 service byte rows"),
    ):
        if (directory / generated).read_bytes() != (ROOT / "analysis" / expected).read_bytes():
            raise ValueError(f"Regenerated data differ: {generated}")
        print(f"PASS {description}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--figures", type=Path, help="check regenerated CSVs in this output directory")
    args = parser.parse_args()
    try:
        if args.figures is None:
            check_manifest()
        else:
            check_figures(args.figures)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
