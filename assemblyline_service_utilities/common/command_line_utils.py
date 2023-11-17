from re import escape, sub
from typing import Dict, List, Optional

X86_64 = "x86_64"
X86 = "x86"

SYSTEM_DRIVE = "c:\\"
SYSTEM_ROOT = "c:\\windows\\"
WINDIR_ENV_VARIABLE = "%windir%"
SAMPLEPATH_ENV_VARIABLE = "%samplepath%"
SZ_USR_TEMP_PATH = "users\\*\\appdata\\local\\temp\\"
SZ_USR_PATH = "users\\*\\"
ARCH_SPECIFIC_DEFAULTS = {
    X86_64: {
        "szProgFiles86": "program files (x86)",
        "szProgFiles64": "program files",
        "szSys86": "syswow64",
        "szSys64": "system32",
    },
    X86: {"szProgFiles86": "program files", "szSys86": "system32"},
}


def _determine_arch(path: str) -> str:
    """
    This method determines what architecture the operating system was built with where the event took place
    :param path: The file path of the image associated with an event
    :return: The architecture of the operating system
    """
    # Clear indicators in a file path of the architecture of the operating system
    if any(item in path for item in ["program files (x86)", "syswow64"]):
        return X86_64
    return X86


def _pattern_substitution(path: str, rule: Dict[str, str]) -> str:
    """
    This method applies pattern rules for explicit string substitution
    :param path: The file path of the image associated with an event
    :param rule: The rule to be applied, containing a pattern and the replacement value
    :return: The modified path, if any rules applied
    """
    if path.startswith(rule["pattern"]):
        path = path.replace(rule["pattern"], rule["replacement"])
    return path


def _regex_substitution(path: str, rule: Dict[str, str]) -> str:
    """
    This method applies a regular expression for implicit string substitution
    :param path: The file path of the image associated with an event
    :param rule: The rule to be applied, containing a pattern and the replacement value
    :return: The modified path, if any rules applied
    """
    rule["regex"] = rule["regex"].split("*")
    rule["regex"] = [escape(e) for e in rule["regex"]]
    rule["regex"] = "[^\\\\]+".join(rule["regex"])
    path = sub(rf"{rule['regex']}", rule["replacement"], path)
    return path


def normalize_path(path: str, arch: Optional[str] = None) -> str:
    """
    This method determines what rules should be applied based on architecture and the applies the rules to the path
    :param path: The file path of the image associated with an event
    :param arch: The architecture of the operating system
    :return: The modified path, if any rules applied
    """
    path = path.lower()
    if not arch:
        arch = _determine_arch(path)

    # Order here matters
    rules: List[Dict[str, str]] = []
    rules.append(
        {
            "pattern": SYSTEM_ROOT + ARCH_SPECIFIC_DEFAULTS[arch]["szSys86"],
            "replacement": "?sys32",
        }
    )
    if arch == X86_64:
        rules.append(
            {
                "pattern": SYSTEM_ROOT + ARCH_SPECIFIC_DEFAULTS[arch]["szSys64"],
                "replacement": "?sys64",
            }
        )
    rules.append(
        {
            "pattern": SYSTEM_DRIVE + ARCH_SPECIFIC_DEFAULTS[arch]["szProgFiles86"],
            "replacement": "?pf86",
        }
    )
    if arch == X86_64:
        rules.append(
            {
                "pattern": SYSTEM_DRIVE + ARCH_SPECIFIC_DEFAULTS[arch]["szProgFiles64"],
                "replacement": "?pf64",
            }
        )
    rules.append({"regex": f"{SYSTEM_DRIVE}{SZ_USR_TEMP_PATH}", "replacement": "?usrtmp\\\\"})
    rules.append({"regex": f"{SYSTEM_DRIVE}{SZ_USR_PATH}", "replacement": "?usr\\\\"})
    rules.append({"pattern": SYSTEM_ROOT, "replacement": "?win\\"})
    rules.append({"pattern": SYSTEM_DRIVE, "replacement": "?c\\"})
    rules.append({"pattern": WINDIR_ENV_VARIABLE, "replacement": "?win"})
    rules.append({"pattern": SAMPLEPATH_ENV_VARIABLE, "replacement": "?usrtmp"})
    for rule in rules:
        if "pattern" in rule:
            path = _pattern_substitution(path, rule)
        if "regex" in rule:
            path = _regex_substitution(path, rule)
    return path
