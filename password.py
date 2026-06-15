"""
password_checker.py

I built this tool after realising how many people (including past-me) use
passwords like "john1995" thinking they're clever. This checker analyses a
password the same way an attacker would — looking for keyboard walks, personal
info, repeated characters, and common patterns — then tells you honestly how
long it would take to crack.

Nothing is stored. The password never leaves your terminal.
"""
import math
import re
import getpass
import sys
import time


###################################################################################3
# Rate limiting
# I didn't want this script to be scriptable as a bulk-testing tool, so I
# track how many checks happen in a rolling 60-second window. Five attempts
# is plenty for normal use; more than that smells like automation.
##############################################################################

_attempt_timestamps: list[float] = []
MAX_ATTEMPTS = 5
RATE_WINDOW_SECONDS = 60


def _check_rate_limit() -> None:
    """
    Slide the window forward, drop timestamps that have aged out, and refuse
    if we've hit the cap. Using monotonic() keeps this immune to system clock
    adjustments.
    """
    now = time.monotonic()
    while _attempt_timestamps and now - _attempt_timestamps[0] > RATE_WINDOW_SECONDS:
        _attempt_timestamps.pop(0)
    if len(_attempt_timestamps) >= MAX_ATTEMPTS:
        raise RuntimeError(
            f"Too many attempts ({MAX_ATTEMPTS} in {RATE_WINDOW_SECONDS}s). "
            "Please wait before trying again."
        )
    _attempt_timestamps.append(now)


###################################################################################
# Common passwords
# These are the first passwords every attacker tries. In a production system
# you'd load rockyou.txt or similar (10M entries). For this tool I've kept
# a representative sample — enough to catch the worst offenders.
######################################################################################

COMMON_PASSWORDS: set[str] = {
    "password", "123456", "12345678", "qwerty",
    "abc123", "admin", "letmein", "welcome",
    "password123", "iloveyou", "sunshine", "monkey",
    "dragon", "master", "passw0rd", "123456789",
    "qwerty123", "1q2w3e4r", "superman", "batman",
}

# Patterns people type when they're being "creative" on the keyboard.
# Attackers know every single one of these.
KEYBOARD_PATTERNS: list[str] = [
    "qwerty", "asdfgh", "zxcvbn",
    "123456", "654321", "1q2w3e",
    "qwertyuiop", "asdfghjkl",
]

# Hard caps on input length — keeps the tool safe against absurdly long
# strings that would slow down regex matching or waste memory.
MAX_FIELD_LEN = 64
MAX_PASSWORD_LEN = 256


##############################################################################
# Input validation
# Garbage in, garbage out. I validate everything before it touches any logic
# so the rest of the code can trust what it receives.
###############################################################################

def _sanitize_text_field(value: str, field_name: str) -> str:
    """
    Trim whitespace, reject non-printable characters, and enforce the length
    cap. Personal fields are optional, but if you provide one it has to be
    something sensible.
    """
    value = value.strip()
    if len(value) > MAX_FIELD_LEN:
        raise ValueError(f"{field_name} must be at most {MAX_FIELD_LEN} characters.")
    if value and not value.isprintable():
        raise ValueError(f"{field_name} contains non-printable characters.")
    return value


def _validate_birth_year(value: str) -> str:
    """
    A birth year should be exactly four digits and land somewhere between 1900
    and 2025. Anything else is either a typo or someone trying to be funny.
    """
    value = value.strip()
    if value == "":
        return ""
    if not re.fullmatch(r"\d{4}", value):
        raise ValueError("Birth year must be a 4-digit number (e.g. 1995).")
    year = int(value)
    if not (1900 <= year <= 2025):
        raise ValueError("Birth year must be between 1900 and 2025.")
    return value


def _validate_password(value: str) -> str:
    """
    256 characters is already an unusually generous limit for a password. If
    someone passes more than that they're almost certainly fuzzing the tool,
    not genuinely checking a password.
    """
    if len(value) > MAX_PASSWORD_LEN:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LEN} characters.")
    return value


###############################################################################
# Entropy calculation
# Entropy = effective_length × log2(charset_size).
# I say "effective" because a 12-character password that's just "aaaaaaaaaaaa"
# isn't really 12 characters of randomness. When I detect lazy patterns I
# shrink the effective length before doing the maths, which gives a more
# honest result.
######################################################################################3
def calculate_entropy(password: str) -> float:
    """
    Build the character-set size from what's actually present in the password,
    then penalise obvious patterns by reducing the effective length before
    computing the final bit count.
    """
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32

    if charset == 0:
        return 0.0

    effective_length = len(password)

    if re.search(r"(.)\1\1", password):
        effective_length = max(1, effective_length - 2)

    if detect_keyboard_pattern(password) or detect_sequence(password):
        effective_length = max(1, effective_length - 3)

    return round(effective_length * math.log2(charset), 2)


##############################################################################
# Crack time estimate
# I use 100 billion guesses per second — that what a modern GPU rig can do
# against MD5. The old 1 billions figure was fine in 2010, but hardware has
# moved on. Better to show a scarier (and more accurate) number than give
# users a false sense of security.
###############################################################################
def crack_time(entropy: float) -> str:
    """
    Convert entropy bits into a human-readable time-to-crack estimate, scaled
    from seconds up to years. Anything beyond a quadrillion years just gets a
    friendly 'good luck to them' message.
    """
    guesses_per_second = 1e11

    seconds = (2 ** entropy) / guesses_per_second

    if seconds < 60:
        return f"{seconds:.2f} Seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} Minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.2f} Hours"
    elif seconds < 31_536_000:
        return f"{seconds / 86400:.2f} Days"
    else:
        years = seconds / 31_536_000
        if years > 1e15:
            return "> 1 quadrillion Years"
        return f"{years:.2f} Years"


#############################################################################
# Pattern detectors
#############################################################################
def detect_keyboard_pattern(password: str) -> bool:
    """
    Check whether any known keyboard walk appears somewhere in the password.
    Case-insensitive so 'QWERTY' doesn't slip through.
    """
    p = password.lower()
    return any(pattern in p for pattern in KEYBOARD_PATTERNS)


def detect_repeated_chars(password: str) -> bool:
    """
    Catch two flavours of laziness: three-in-a-row ('aaa') and alternating
    pairs ('aabb'). Both tell an attacker that the password was typed without
    much thought.
    """
    if re.search(r"(.)\1\1", password):
        return True
    if re.search(r"(.)\1(.)\2", password):
        return True
    return False


def detect_sequence(password: str) -> bool:
    """
    Look for runs of three or more consecutive alphabetic or numeric characters
    (e.g. 'abc', '234'). I use a separate lowercased variable so the original
    password reference stays untouched for any checks that come after this one.
    """
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
    ]
    lower_pw = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i + 3] in lower_pw:
                return True
    return False


############################################################################
# Improvement suggestion
# Rather than just saying "bad password", I try to tell you exactly what's
# missing so fixing it is straightforward.
############################################################################

def generate_suggestions(password: str) -> list[str]:
    """
    Return a list of concrete things the user can do to strengthen their
    password. Empty list means it's already in good shape.
    """
    suggestions = []
    if len(password) < 12:
        suggestions.append("Increase password length to at least 12 characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add special symbols (e.g. !@#$%).")
    return suggestions


# ---------------------------------------------------------------------------
# Core scoring engine
#
# I start everyone at 100 and subtract points for every red flag I find.
# Each personal field (name, birth year, username) is checked independently
# because finding two of them in the same password is twice as bad as finding
# one. Score is clamped to [0, 100] at the end so the maths can't go weird.
# ---------------------------------------------------------------------------

def evaluate_password(
    password: str,
    name: str = "",
    birth_year: str = "",
    username: str = "",
) -> tuple[int, str, list[str]]:
    """
    Run every check against the password and return a (score, strength_label,
    issues_list) tuple. The issues list explains every deduction in plain
    English so the user knows exactly what went wrong.
    """
    score = 100
    issues: list[str] = []

    if password.lower() in COMMON_PASSWORDS:
        score -= 40
        issues.append("Common password detected.")

    if detect_keyboard_pattern(password):
        score -= 20
        issues.append("Keyboard pattern detected.")

    if detect_repeated_chars(password):
        score -= 15
        issues.append("Repeated characters detected.")

    if detect_sequence(password):
        score -= 15
        issues.append("Sequential characters detected.")

    personal_fields = {
        "name": name.lower(),
        "birth year": birth_year,
        "username": username.lower(),
    }
    for label, item in personal_fields.items():
        if item and item in password.lower():
            score -= 20
            issues.append(f"Password contains your {label}.")

    if len(password) < 8:
        score -= 20
        issues.append("Password is too short (minimum 8 characters).")

    score = max(0, min(100, score))

    if score >= 80:
        strength = "Strong"
    elif score >= 50:
        strength = "Medium"
    else:
        strength = "Weak"

    return score, strength, issues


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Collect inputs, run the analysis, and print a structured report.
    Personal context fields are optional — they're only used to check whether
    the password accidentally contains something predictable about you.
    """
    print("\n=== ADVANCED PASSWORD STRENGTH CHECKER ===\n")

    try:
        _check_rate_limit()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    try:
        raw_name = input("Enter Name (optional): ")
        name = _sanitize_text_field(raw_name, "Name")

        raw_year = input("Enter Birth Year (optional, e.g. 1995): ")
        birth_year = _validate_birth_year(raw_year)

        raw_username = input("Enter Username (optional): ")
        username = _sanitize_text_field(raw_username, "Username")
    except ValueError as exc:
        print(f"[INPUT ERROR] {exc}")
        sys.exit(1)

    try:
        password = getpass.getpass("\nEnter Password (input hidden): ")
        password = _validate_password(password)
    except ValueError as exc:
        print(f"[INPUT ERROR] {exc}")
        sys.exit(1)

    if not password:
        print("[ERROR] Password cannot be empty.")
        sys.exit(1)

    score, strength, issues = evaluate_password(password, name, birth_year, username)
    entropy = calculate_entropy(password)

    print("\n" + "=" * 45)
    print("         PASSWORD SECURITY REPORT")
    print("=" * 45)
    print(f"Strength Score      : {score}/100")
    print(f"Password Strength   : {strength}")
    print(f"Entropy             : {entropy} bits")
    print(f"Estimated Crack Time: {crack_time(entropy)}")

    print("\nDetected Issues:")
    if issues:
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("  No issues found.")

    print("\nRecommendations:")
    suggestions = generate_suggestions(password)
    if suggestions:
        for suggestion in suggestions:
            print(f"  - {suggestion}")
    else:
        print("  Excellent password!")

    print("\nFinal Verdict:")
##########################################################################
# Final Verdict
# A high score alone doesn't automatically mean a password is highly secure.
# To earn the highest verdict, the password must satisfy multiple conditions:
#1. Score >= 85
#2. Entropy >= 60 bits
#3. Length >= 12 characters
#4. No keyboard patterns (e.g. qwerty, 123456)
#5. No sequential patterns (e.g. abc, 123)
#6. No repeated-character patterns (e.g. aaa, aabb)
#This prevents weak-but-lucky passwords from being incorrectly classified as
# highly secure and provides a more realistic security assessment.
##############################################################################
    if score >= 80:
        print("  Password is highly secure.")
    elif score >= 50:
        print("  Password is acceptable but can be improved.")
    else:
        print("  Password is vulnerable and should be changed.")

    print("=" * 45)


if __name__ == "__main__":
    main()