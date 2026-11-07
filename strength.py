"""Password strength heuristic used before accepting a new password."""

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "~@#$%^&*()_+-=,./:;|"
COMMON_BAD = ["password", "qwerty", "abc123", "111111", "123456"]


def check_strength(password):
    has_lower = has_upper = has_digit = has_symbol = False
    repeated_chars = has_sequence = False

    for i, ch in enumerate(password):
        if ch in LOWER:
            has_lower = True
        if ch in UPPER:
            has_upper = True
        if ch in DIGITS:
            has_digit = True
        if ch in SYMBOLS:
            has_symbol = True

        if i > 0 and password[i] == password[i - 1]:
            repeated_chars = True

        if i >= 2:
            a, b, c = password[i - 2], password[i - 1], password[i]

            if a in LOWER and b in LOWER and c in LOWER:
                if ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1:
                    has_sequence = True

            if a in UPPER and b in UPPER and c in UPPER:
                if ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1:
                    has_sequence = True

            if a.isdigit() and b.isdigit() and c.isdigit():
                if int(b) == int(a) + 1 and int(c) == int(b) + 1:
                    has_sequence = True

    score = 0

    if len(password) >= 8:
        score += 2
    if len(password) >= 12:
        score += 1

    if has_lower:
        score += 2
    if has_upper:
        score += 2
    if has_digit:
        score += 2
    if has_symbol:
        score += 2

    if repeated_chars:
        score -= 1
    if has_sequence:
        score -= 2

    pw_lower = password.lower()
    for bad in COMMON_BAD:
        if bad in pw_lower:
            score -= 3

    return max(0, min(10, score))
