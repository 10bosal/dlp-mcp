from pathlib import Path

import pytest

from dlp_mcp.decrypt import extract_docx_text


def test_extract_docx_text():
    docx_path = Path(__file__).resolve().parents[2] / "dlp-encrypt/tests/answers.docx"
    if not docx_path.is_file():
        pytest.skip("answers.docx not available")

    text = extract_docx_text(docx_path.read_bytes())
    assert text
    assert isinstance(text, str)
