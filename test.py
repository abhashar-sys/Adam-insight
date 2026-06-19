import numpy as np

def inspect_spread(values, label):
    q1 = np.percentile(values, 25)
    q3 = np.percentile(values, 75)
    iqr = q3 - q1
    print(f"\n{label}")
    print(f"  min   = {min(values):,.0f}")
    print(f"  Q1    = {q1:,.0f}")
    print(f"  median= {np.percentile(values, 50):,.0f}")
    print(f"  Q3    = {q3:,.0f}")
    print(f"  max   = {max(values):,.0f}")
    print(f"  IQR   = {iqr:,.0f}")
    print(f"  IQR threshold (Q3 + 1.5*IQR) = {q3 + 1.5*iqr:,.0f}")

inspect_spread(bps, "BPS")
inspect_spread(pps, "PPS")