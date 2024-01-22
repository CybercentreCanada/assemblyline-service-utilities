from assemblyline_service_utilities.testing.helper import IssueHelper, TestHelper


def test_file_compare():
    TestHelper.__init__ = lambda self: None
    th = TestHelper()
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
    th._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
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
    th._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
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
    th._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
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
    th._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
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
    th._file_compare(ih, ih.TYPE_EXTRACTED, original, new)
    assert ih.TYPE_EXTRACTED in ih.get_issues()
    assert ih.get_issues()[ih.TYPE_EXTRACTED] == [
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-b' has changed. hash-a -> hash-c"),
        (ih.ACTION_CHANGED, "The sha256 of the file 'name-c' has changed. hash-a -> hash-c"),
    ]
