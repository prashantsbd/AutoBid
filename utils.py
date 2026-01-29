def _int_or_default(val: str | None, default: int) -> int:
    """
    Convert val to int safely.
    Returns default if val is None, empty string, or invalid number.
    """
    try:
        if val is None:
            return default
        val_str = str(val).strip()
        return int(val_str) if val_str else default
    except (ValueError, TypeError):
        return default

def _nearest_10_up(n: int) -> int:
    """
    Round n up to nearest multiple of 10
    """
    return ((n + 9) // 10) * 10
