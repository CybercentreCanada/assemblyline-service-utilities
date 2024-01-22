from assemblyline_service_utilities.testing.helper import IssueHelper, TestHelper


def test_file_compare_identical():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.get_issues() == {}


def test_file_compare_hash_change():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-d"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-c' has changed. hash-c -> hash-d"),
    ]


def test_file_compare_name_change():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-d", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The name of the file 'hash-b' has changed. name-b -> name-d"),
    ]


def test_file_compare_new_file():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
        {"name": "name-d", "sha256": "hash-d"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_ADDED, "File 'name-d [hash-d]' added to the file list."),
    ]


def test_file_compare_two_new_file():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
        {"name": "name-d", "sha256": "hash-d"},
        {"name": "name-e", "sha256": "hash-e"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_ADDED, "File 'name-d [hash-d]' added to the file list."),
        (ih.ACTION_ADDED, "File 'name-e [hash-e]' added to the file list."),
    ]


def test_file_compare_missing_file():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_MISSING, "File 'name-c [hash-c]' missing from the file list."),
    ]


def test_file_compare_two_missing_file():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_MISSING, "File 'name-b [hash-b]' missing from the file list."),
        (ih.ACTION_MISSING, "File 'name-c [hash-c]' missing from the file list."),
    ]


def test_file_compare_missing_and_new_file():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-d", "sha256": "hash-d"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_MISSING, "File 'name-c [hash-c]' missing from the file list."),
        (ih.ACTION_ADDED, "File 'name-d [hash-d]' added to the file list."),
    ]


def test_file_compare_duplicate_hashes():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.get_issues() == {}

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-c"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-a' has changed. hash-a -> hash-c"),
    ]

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-c"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-b' has changed. hash-a -> hash-c"),
    ]

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-c' has changed. hash-a -> hash-c"),
    ]

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-c"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-b' has changed. hash-a -> hash-c"),
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-c' has changed. hash-a -> hash-c"),
    ]

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-a"},
    ]
    new = [
        {"name": "name-b", "sha256": "hash-a"},
        {"name": "name-c", "sha256": "hash-a"},
        {"name": "name-d", "sha256": "hash-a"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_MISSING, "File 'name-a [hash-a]' missing from the file list."),
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-b' has changed. hash-b -> hash-a"),
        (ih.ACTION_ADDED, "File 'name-d [hash-a]' added to the file list."),
    ]


def test_file_compare_duplicate_names():
    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-a", "sha256": "hash-b"},
        {"name": "name-a", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The name of the file 'hash-b' has changed. name-a -> name-b"),
        (ih.ACTION_CHANGED, "The name of the file 'hash-c' has changed. name-a -> name-c"),
    ]

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-a", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-d", "sha256": "hash-a"},
        {"name": "name-a", "sha256": "hash-b"},
        {"name": "name-c", "sha256": "hash-c"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The name of the file 'hash-a' has changed. name-a -> name-d"),
        (ih.ACTION_CHANGED, "The name of the file 'hash-b' has changed. name-b -> name-a"),
        (ih.ACTION_CHANGED, "The name of the file 'hash-c' has changed. name-a -> name-c"),
    ]

    ih = IssueHelper()
    original = [
        {"name": "name-a", "sha256": "hash-a"},
        {"name": "name-b", "sha256": "hash-b"},
        {"name": "name-a", "sha256": "hash-c"},
    ]
    new = [
        {"name": "name-a", "sha256": "hash-b"},
        {"name": "name-a", "sha256": "hash-c"},
        {"name": "name-a", "sha256": "hash-d"},
    ]
    TestHelper._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_MISSING, "File 'name-a [hash-a]' missing from the file list."),
        (ih.ACTION_CHANGED, "The name of the file 'hash-b' has changed. name-b -> name-a"),
        (ih.ACTION_ADDED, "File 'name-a [hash-d]' added to the file list."),
    ]
