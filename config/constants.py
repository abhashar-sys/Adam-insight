# ── Peak-detection constants ─────────────────────────────────────
TUKEY_FENCE = 1.5
FALLBACK_PERCENTILE = 95
BUCKET_SECONDS = 10             # 10-second aggregation buckets
MIN_GAP_BUCKETS = 12            # ~2 minutes at 10s buckets
TOP_N = 5

# ── Baseline constants ───────────────────────────────────────────
TRAILING_BASELINE_DAYS = 6
SECONDS_PER_DAY = 86_400