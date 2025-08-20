#python3
# password_generator.py
# CodSoft Task: Password Generator

import argparse
import secrets
import string
import sys
from typing import List

AMBIGUOUS = "Il1O0|`'\"(){}[]<>:;,.~"

def build_pool(use_lower: bool, use_upper: bool, use_digits: bool, use_symbols: bool, no_ambiguous: bool) -> List[str]:
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        # A safe symbol set (common keyboard symbols)
        pools.append("!@#$%^&*_-+=?/\\")
    if not pools:
        raise ValueError("Select at least one character set (lower/upper/digits/symbols).")

    # Merge and optionally remove ambiguous characters
    merged = "".join(pools)
    if no_ambiguous:
        merged = "".join(ch for ch in merged if ch not in AMBIGUOUS)
        if not merged:
            raise ValueError("Character pool became empty after removing ambiguous characters.")

    return pools, merged

def generate_password(length: int = 12,
                      use_lower: bool = True,
                      use_upper: bool = True,
                      use_digits: bool = True,
                      use_symbols: bool = True,
                      no_ambiguous: bool = False) -> str:
    if length < 4:
        raise ValueError("Length should be at least 4.")

    pools, pool_all = build_pool(use_lower, use_upper, use_digits, use_symbols, no_ambiguous)

    # Ensure at least one char from each selected pool
    sysrand = secrets.SystemRandom()
    password_chars = []
    for p in pools:
        # Respect ambiguous removal for the per-pool pick too
        candidates = p if not no_ambiguous else "".join(ch for ch in p if ch not in AMBIGUOUS)
        if not candidates:
            continue
        password_chars.append(sysrand.choice(candidates))

    # Fill the remaining length
    while len(password_chars) < length:
        password_chars.append(sysrand.choice(pool_all))

    # Shuffle to avoid predictable positions
    sysrand.shuffle(password_chars)
    return "".join(password_chars)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a strong random password."
    )
    parser.add_argument("-l", "--length", type=int, default=12, help="Password length (default: 12)")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    parser.add_argument("--no-ambiguous", action="store_true", help="Avoid ambiguous characters (Il1O0| etc.)")
    parser.add_argument("-n", "--num", type=int, default=1, help="How many passwords to generate (default: 1)")
    return parser.parse_args()

def main():
    args = parse_args()

    use_lower  = not args.no_lower
    use_upper  = not args.no_upper
    use_digits = not args.no_digits
    use_symbols= not args.no_symbols

    try:
        for _ in range(max(1, args.num)):
            print(
                generate_password(
                    length=args.length,
                    use_lower=use_lower,
                    use_upper=use_upper,
                    use_digits=use_digits,
                    use_symbols=use_symbols,
                    no_ambiguous=args.no_ambiguous
                )
            )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        # Simple interactive fallback
        print("\nInteractive mode:", file=sys.stderr)
        try:
            length = int(input("Enter length (e.g., 12): ").strip() or "12")
            use_lower  = input("Include lowercase? (y/n) [y]: ").strip().lower() != "n"
            use_upper  = input("Include uppercase? (y/n) [y]: ").strip().lower() != "n"
            use_digits = input("Include digits? (y/n) [y]: ").strip().lower() != "n"
            use_symbols= input("Include symbols? (y/n) [y]: ").strip().lower() != "n"
            no_amb     = input("Avoid ambiguous chars? (y/n) [n]: ").strip().lower() == "y"
            print(generate_password(length, use_lower, use_upper, use_digits, use_symbols, no_amb))
        except Exception as ex:
            print(f"Still couldn’t generate password: {ex}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
