def fingerprint(details: dict) -> tuple:
    return tuple(sorted((key, type(value).__name__) for key, value in details.items()))