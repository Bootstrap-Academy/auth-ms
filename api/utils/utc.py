from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.utcnow().replace(tzinfo=timezone.utc)


def utcfromtimestamp(ts: float) -> datetime:
    return datetime.utcfromtimestamp(ts).replace(tzinfo=timezone.utc)
