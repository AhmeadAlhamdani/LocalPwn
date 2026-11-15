from localpwn.report import render_html

def test_escapes_hostile_content():
    page=render_html({"assessment":{"target":"<script>alert(1)</script>","status":"complete","id":"abc"},"findings":[],"actions":[],"artifacts":[]})
    assert "&lt;script&gt;" in page
    assert "<script>" not in page
