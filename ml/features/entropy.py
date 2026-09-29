"""
RansomShield AI — Entropy Calculator
Phase 1: Machine Learning & Feature Pipeline

Computes Shannon Entropy for file content buffers and data blocks to identify
encrypted/compressed ransomware payloads.
"""

import math
from typing import Union


def calculate_shannon_entropy(data: Union[bytes, bytearray, str]) -> float:
    """
    Calculate the Shannon Entropy of a byte buffer or string.
    
    Shannon Entropy ranges from:
    - 0.0 (completely uniform data, e.g. all 0x00 bytes or single character)
    - ~3.5 - 5.0 (typical plain text, source code, ASCII documents)
    - ~5.0 - 6.5 (compiled binaries, images, structured archives)
    - ~7.2 - 8.0 (high-entropy encrypted data, strong compression, ransomware ciphertext)
    
    Formula:
        H(X) = - sum_{i=0}^{255} ( p(x_i) * log2(p(x_i)) )
    """
    if not data:
        return 0.0
    
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    
    length = len(data)
    if length == 0:
        return 0.0
    
    # Count byte frequencies across the 256 possible byte values
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
            
    return round(float(entropy), 4)


def is_high_entropy(data: Union[bytes, str], threshold: float = 7.2) -> bool:
    """Returns True if the byte buffer exhibits entropy above the ransomware encryption threshold."""
    return calculate_shannon_entropy(data) >= threshold


if __name__ == "__main__":
    import os
    
    plain_text = b"Hello world! This is normal plaintext user document data with low entropy."
    random_bytes = os.urandom(4096)
    zero_bytes = b"\x00" * 4096
    
    print(f"Plaintext entropy:  {calculate_shannon_entropy(plain_text)} (Expected ~4.0)")
    print(f"Random/Enc entropy: {calculate_shannon_entropy(random_bytes)} (Expected ~7.9+)")
    print(f"Zero bytes entropy: {calculate_shannon_entropy(zero_bytes)} (Expected 0.0)")
