LEVELS = ("disable", "trace", "debug", "info", "warn", "error", "fatal", "panic")
DEFAULT = "info"


def build(level="info"):
    """Build a sing-box log config block."""
    if level == "disable":
        return {"disabled": True}
    if level not in LEVELS:
        raise ValueError(f"Unknown log level: {level!r}, expected one of {LEVELS}")
    return {"level": level}
