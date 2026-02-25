from untrusted_content_tool.scanner import split_windows


def test_split_windows_with_overlap() -> None:
    content = "a" * 600
    windows = split_windows(content, window_size=250, overlap=50)

    assert len(windows) == 3
    assert windows[0].start == 0
    assert windows[1].start == 200
    assert windows[2].start == 400
    assert windows[2].end == 600


def test_split_windows_empty_content() -> None:
    windows = split_windows("", window_size=250, overlap=50)

    assert len(windows) == 1
    assert windows[0].content == ""
