import hashlib


def get_gravatar_url(email: str) -> str:
    _hash = hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()
    return f"https://www.gravatar.com/avatar/{_hash}"
