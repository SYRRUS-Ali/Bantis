import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
# Tests drive correlation themselves; a background pass would race them.
os.environ.setdefault("CORRELATION_INTERVAL_SECONDS", "0")