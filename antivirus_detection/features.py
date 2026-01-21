from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pefile

# Default feature order expected by the included model.
# If you retrain, the model will typically ship its own feature list file.
FEATURE_NAMES: Tuple[str, ...] = (
    "Machine",
    "SizeOfOptionalHeader",
    "Characteristics",
    "ImageBase",
    "MajorOperatingSystemVersion",
    "MajorSubsystemVersion",
    "Subsystem",
    "DllCharacteristics",
    "SectionsMinEntropy",
    "SectionsMaxEntropy",
    "ResourcesMinEntropy",
    "ResourcesMaxEntropy",
    "VersionInformationSize",
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    # bytes in py3 are ints 0-255
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return float(entropy)


def _resource_entropies(pe: pefile.PE) -> List[float]:
    """Best-effort extraction of resource entry entropies.

    pefile's resource structures can vary depending on parsing; we keep this robust:
    - If resources are absent or parsing fails, return [].
    """
    entropies: List[float] = []
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return entropies

        def walk(entries):
            for e in entries:
                if hasattr(e, "data") and hasattr(e.data, "struct"):
                    try:
                        rva = e.data.struct.OffsetToData
                        size = e.data.struct.Size
                        data = pe.get_memory_mapped_image()[rva : rva + size]
                        entropies.append(_shannon_entropy(data))
                    except Exception:
                        pass
                if hasattr(e, "directory") and hasattr(e.directory, "entries"):
                    walk(e.directory.entries)

        walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    except Exception:
        return []
    return entropies


def _version_info_size(pe: pefile.PE) -> int:
    size = 0
    try:
        if not hasattr(pe, "FileInfo") or pe.FileInfo is None:
            return 0
        for entry in pe.FileInfo:
            if hasattr(entry, "StringTable"):
                for st in entry.StringTable:
                    # st.entries is a dict
                    size += len(getattr(st, "entries", {}) or {})
    except Exception:
        return 0
    return int(size)


def extract_pe_features(file_path: str | Path) -> Dict[str, Any]:
    """Extract the feature dictionary used by the shipped model.

    Supports Windows PE files (.exe/.dll/.sys). Raises ValueError for invalid files.
    """
    fpath = Path(file_path)
    if not fpath.exists():
        raise ValueError(f"File not found: {fpath}")

    try:
        pe = pefile.PE(str(fpath), fast_load=False)
    except Exception as e:
        raise ValueError(f"Not a valid PE file: {fpath.name}") from e

    res: Dict[str, Any] = {}
    # Header fields
    res["Machine"] = int(pe.FILE_HEADER.Machine)
    res["SizeOfOptionalHeader"] = int(pe.FILE_HEADER.SizeOfOptionalHeader)
    res["Characteristics"] = int(pe.FILE_HEADER.Characteristics)

    # Optional header fields
    res["ImageBase"] = int(pe.OPTIONAL_HEADER.ImageBase)
    res["MajorOperatingSystemVersion"] = int(
        getattr(pe.OPTIONAL_HEADER, "MajorOperatingSystemVersion", 0)
    )
    res["MajorSubsystemVersion"] = int(getattr(pe.OPTIONAL_HEADER, "MajorSubsystemVersion", 0))
    res["Subsystem"] = int(pe.OPTIONAL_HEADER.Subsystem)
    res["DllCharacteristics"] = int(pe.OPTIONAL_HEADER.DllCharacteristics)

    # Section entropy
    try:
        section_entropies = [float(s.get_entropy()) for s in pe.sections] if pe.sections else []
    except Exception:
        section_entropies = []
    res["SectionsMinEntropy"] = min(section_entropies) if section_entropies else 0.0
    res["SectionsMaxEntropy"] = max(section_entropies) if section_entropies else 0.0

    # Resource entropy
    r_ent = _resource_entropies(pe)
    res["ResourcesMinEntropy"] = min(r_ent) if r_ent else 0.0
    res["ResourcesMaxEntropy"] = max(r_ent) if r_ent else 0.0

    # Version info
    res["VersionInformationSize"] = _version_info_size(pe)

    return res


def vectorize_features(
    feature_dict: Dict[str, Any], ordered_features: Iterable[str]
) -> List[float]:
    """Return a numeric feature vector in the requested order."""
    vec: List[float] = []
    for name in ordered_features:
        val = feature_dict.get(name, 0)
        try:
            vec.append(float(val))
        except Exception:
            vec.append(0.0)
    return vec
