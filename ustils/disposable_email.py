import os

_LIST_PATH = os.path.join(os.path.dirname(__file__), "disposable_domains.txt")

# Domains observed in the wild that aren't yet in the upstream list.
_EXTRA_BLOCKED_DOMAINS = {
    "hotkev.com",
    "perparmy.com",
}


def _load_blocked_domains() -> set:
    domains = set(_EXTRA_BLOCKED_DOMAINS)
    try:
        with open(_LIST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
    except FileNotFoundError:
        pass
    return domains


_BLOCKED_DOMAINS = _load_blocked_domains()


def is_disposable_email(email: str) -> bool:
    domain = email.strip().lower().rsplit("@", 1)[-1]
    return domain in _BLOCKED_DOMAINS
