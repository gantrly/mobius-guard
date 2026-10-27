"""Exact and near-duplicate detection.

Near duplicates are found with MinHash over character 5-gram sets and grouped into
clusters; a suite puts a whole cluster in one split, so a near copy of a test item can't
sit in the calibration split (or in a baseline's training data).
"""

# numpy's stubs leave some overloads partially unknown under strict mode.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import cast

import numpy as np
import numpy.typing as npt

from .items import normalize

SHINGLE = 5
N_PERM = 128
BANDS = 32  # 32 bands x 4 rows: pairs above ~0.5 Jaccard become candidates
JACCARD = 0.8  # candidates at or above this estimated Jaccard are duplicates

_U64 = np.uint64
_rng = np.random.default_rng(20261027)
_A = _rng.integers(1, 2**63, N_PERM, dtype=np.int64).astype(_U64) | _U64(1)
_B = _rng.integers(0, 2**63, N_PERM, dtype=np.int64).astype(_U64)
_P = _U64(1_000_003)


def _shingle_hashes(text: str) -> npt.NDArray[np.uint64]:
    codes = np.frombuffer(normalize(text).encode("utf-32-le"), dtype=np.uint32).astype(_U64)
    if len(codes) < SHINGLE:
        codes = np.concatenate([codes, np.zeros(SHINGLE - len(codes), dtype=_U64)])
    n = len(codes) - SHINGLE + 1
    h = np.zeros(n, dtype=_U64)
    with np.errstate(over="ignore"):
        for j in range(SHINGLE):
            h = h * _P + codes[j : j + n]
    return np.unique(h)


def signature(text: str) -> npt.NDArray[np.uint64]:
    """MinHash signature: for each of N_PERM hash functions, the minimum over shingles."""
    h = _shingle_hashes(text)
    with np.errstate(over="ignore"):
        sig = (np.outer(_A, h) + _B[:, None]).min(axis=1)
    return cast("npt.NDArray[np.uint64]", sig)


def similarity(a: npt.NDArray[np.uint64], b: npt.NDArray[np.uint64]) -> float:
    """Estimated Jaccard similarity of the two shingle sets."""
    return float(np.mean(a == b))


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        a, b = self.find(i), self.find(j)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def clusters(texts: Sequence[str], *, threshold: float = JACCARD) -> list[int]:
    """Cluster index for each text: exact (normalised) and near duplicates share one.

    The index is the position of the cluster's first member, so it is deterministic for a
    given input order.
    """
    n = len(texts)
    uf = _UnionFind(n)
    first: dict[str, int] = {}
    for i, t in enumerate(texts):
        key = normalize(t)
        if key in first:
            uf.union(first[key], i)
        else:
            first[key] = i

    reps = sorted(first.values())
    sigs = {i: signature(texts[i]) for i in reps}
    rows = N_PERM // BANDS
    # Each bucket keeps a few representatives; a new text is compared with those only.
    buckets: dict[tuple[int, bytes], list[int]] = defaultdict(list)
    for i in reps:
        sig = sigs[i]
        for band in range(BANDS):
            key = (band, sig[band * rows : (band + 1) * rows].tobytes())
            members = buckets[key]
            for j in members:
                if uf.find(i) != uf.find(j) and similarity(sig, sigs[j]) >= threshold:
                    uf.union(i, j)
            if len(members) < 8:
                members.append(i)
    return [uf.find(i) for i in range(n)]
