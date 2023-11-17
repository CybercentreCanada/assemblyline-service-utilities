import pytest
from assemblyline_service_utilities.common.command_line_utils import (
    _determine_arch,
    _pattern_substitution,
    _regex_substitution,
    normalize_path,
)


@pytest.mark.parametrize(
    "path, expected_result",
    [
        ("blah", "x86"),
        ("C:\\program files\\blah", "x86"),
        ("C:\\program files (x86)\\blah", "x86_64"),
        ("C:\\syswow64\\blah", "x86_64"),
    ],
)
def test_determine_arch(path, expected_result):
    assert _determine_arch(path) == expected_result


@pytest.mark.parametrize(
    "path, rule, expected_result",
    [
        ("blah", {"pattern": "", "replacement": ""}, "blah"),
        ("blah", {"pattern": "ah", "replacement": "ue"}, "blah"),
        ("blah", {"pattern": "bl", "replacement": "y"}, "yah"),
    ],
)
def test_pattern_substitution(path, rule, expected_result):
    assert _pattern_substitution(path, rule) == expected_result


@pytest.mark.parametrize(
    "path, rule, expected_result",
    [
        ("blah", {"regex": "", "replacement": ""}, "blah"),
        ("blah", {"regex": "bl*ah", "replacement": "bl"}, "blah"),
        ("blah", {"regex": "\\bl*ah", "replacement": "bl"}, "blah"),
        ("blaah", {"regex": "bl*ah", "replacement": "blue"}, "blue"),
    ],
)
def test_regex_substitution(path, rule, expected_result):
    assert _regex_substitution(path, rule) == expected_result


@pytest.mark.parametrize(
    "path, arch, expected_result",
    [
        ("blah", None, "blah"),
        ("C:\\Program Files\\Word.exe", None, "?pf86\\word.exe"),
        ("C:\\Program Files (x86)\\Word.exe", None, "?pf86\\word.exe"),
        ("C:\\Program Files (x86)\\Word.exe", "x86_64", "?pf86\\word.exe"),
        ("C:\\Windows\\System32\\Word.exe", None, "?sys32\\word.exe"),
        ("C:\\Windows\\SysWow64\\Word.exe", None, "?sys32\\word.exe"),
        ("C:\\Windows\\SysWow64\\Word.exe", "x86", "?win\\syswow64\\word.exe"),
        ("C:\\Windows\\SysWow64\\Word.exe", "x86_64", "?sys32\\word.exe"),
        (
            "C:\\Users\\buddy\\AppData\\Local\\Temp\\Word.exe",
            None,
            "?usrtmp\\word.exe",
        ),
        ("C:\\Users\\buddy\\Word.exe", None, "?usr\\word.exe"),
        ("%WINDIR%\\explorer.exe", None, "?win\\explorer.exe"),
        ("%SAMPLEPATH%\\diagerr.exe", None, "?usrtmp\\diagerr.exe"),
    ],
)
def test_normalize_path(path, arch, expected_result):
    assert normalize_path(path, arch) == expected_result
