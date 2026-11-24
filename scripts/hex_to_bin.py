#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 feiyehua
"""Convert whitespace-separated hexadecimal words to little-endian bytes."""

import argparse
import re
import sys
from pathlib import Path


def read_stdin():
    if not sys.stdin.isatty():
        return sys.stdin.read()

    print("Paste hexadecimal words, then press Enter on an empty line.", file=sys.stderr)
    lines = []
    for line in sys.stdin:
        if not line.strip():
            break
        lines.append(line)
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default="-", help="hex text file (default: stdin)")
    parser.add_argument("output", help="binary output file, or - for stdout")
    args = parser.parse_args()

    try:
        if args.input == "-":
            source = read_stdin()
        else:
            source = Path(args.input).read_text(encoding="utf-8-sig")

        data = bytearray()
        for line_number, line in enumerate(source.splitlines(), start=1):
            for token in line.split():
                if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", token):
                    raise ValueError(f"line {line_number}: invalid hexadecimal word {token!r}")
                value = int(token, 16)
                if value.bit_length() > 64:
                    raise ValueError(f"line {line_number}: {token!r} exceeds 64 bits")
                data.extend(value.to_bytes(8, byteorder="little"))

        if args.output == "-":
            sys.stdout.buffer.write(data)
        else:
            Path(args.output).write_bytes(data)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
