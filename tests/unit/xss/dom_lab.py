"""
Local fixture replicating classic XSS lab shapes.
"""
from __future__ import annotations

import functools
import http.server
import json
import pathlib
import shutil
import tempfile
import threading
import time
import urllib.parse

HOME = (
    '<!doctype html><html><body><h1>Shop</h1>'
    '<p><a href="/comment">Post a comment</a></p>'
    '<p><a href="/angular">Search</a></p>'
    '<p><a href="/search">Product search</a></p>'
    '<p><a href="/product">Catalog search</a></p>'
    '<script>console.log("home page, nothing tainted here");</script>'
    "</body></html>"
)

FEEDBACK = """<!doctype html><html><body>
<a id="backLink" href="/">Back</a>
<a id="safeLink" href="/">Safe</a>
<script>
function $(sel) {
  if (typeof sel === 'function') { sel(); return; }
  var el = document.querySelector(sel);
  return { attr: function (n, v) { el.setAttribute(n, v); return this; } };
}
</script>
<script>
$(function () {
  var returnPath = new URLSearchParams(location.search).get('returnPath');
  $('#backLink').attr('href', returnPath);
});
</script>
</body></html>"""

HASH = """<!doctype html><html><body>
<div id="comments"></div>
<script>
function $(sel) {
  if (typeof sel === 'function') { sel(); return; }
  if (sel === window) {
    return { on: function (evt, fn) { window.addEventListener(evt, fn); return this; } };
  }
  var el = (typeof sel === 'string' && sel.charAt(0) === '<')
    ? (function () {
        var t = document.createElement('div'); t.innerHTML = sel; return t.firstChild;
      })()
    : document.querySelector(sel);
  return {
    text: function (t) { el.textContent = t; return this; },
    html: function (h) { el.innerHTML = h; return this; },
    attr: function (n, v) { el.setAttribute(n, v); return this; }
  };
}
</script>
<script>
function render() {
  var post = decodeURIComponent(location.hash.slice(1));
  var safe = $('<div>').text(post);
  $('#comments').html(post);
}
$(window).on('hashchange', render);
</script>
</body></html>"""

COMMENT_FORM = """<!doctype html><html><body>
<h1>Post a comment</h1>
<form method="post" action="/post/comment">
  <p><textarea name="comment" rows="4" cols="40"></textarea></p>
  <p><input type="text" name="name" placeholder="Name"></p>
  <p><input type="text" name="website" placeholder="Website"></p>
  <p><button type="submit">Post</button></p>
</form>
</body></html>"""

POST_VIEW = (
    "<!doctype html><html><body>"
    "<h1>Comment #{num}</h1>"
    '<p>By <a id="author" href="{website}">{name}</a></p>'
    '<p id="commentBody">{comment}</p>'
    '<p><a href="/">Back to home</a></p>'
    "</body></html>"
)

REFLECTED_DOM = """<!doctype html><html><body>
<h1>Search results</h1>
<form action="/search" method="get">
  <input type="text" name="search" value="">
  <button type="submit">Search</button>
</form>
<div id="results"></div>
<script>
var results = JSON.parse('{"q":"@@SEARCH@@"}');
if (results.q) { eval('renderResults(' + JSON.stringify(results) + ')'); }
function renderResults(r) { document.getElementById('results').textContent = r.q; }
</script>
</body></html>"""

SEARCH_JSON_PAGE = """<!doctype html><html><body>
<h1>Search</h1>
<form action="/product" method="get">
  <input type="text" name="search" value="">
  <button type="submit">Search</button>
</form>
<div id="results"></div>
<script>
var term = new URLSearchParams(location.search).get('search');
var xhr = new XMLHttpRequest();
xhr.open('GET', '/searchResults?search=' + encodeURIComponent(term));
xhr.onload = function () {
  eval('var searchResultsObj = ' + this.responseText);
  document.getElementById('results').textContent = searchResultsObj.searchTerm;
};
xhr.send();
</script>
</body></html>"""

ANGULAR_TEMPLATE = """<!doctype html><html><body ng-app>
<form action="/angular" method="get">
  <input type="text" name="search" value="">
  <button type="submit">Search</button>
</form>
<h1>0 search results for '@@SEARCH@@'</h1>
<script>
(function () {
  window.$on = function () {};
  function compile(node) {
    var walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, null);
    var texts = [];
    while (walker.nextNode()) { texts.push(walker.currentNode); }
    texts.forEach(function (tn) {
      var m = tn.nodeValue.match(/\\{\\{(.+)\\}\\}/);
      if (!m) { return; }
      try {
        tn.nodeValue = String(Function('return (' + m[1] + ')')());
      } catch (e) { /* non-expression text stays as-is */ }
    });
  }
  document.addEventListener('DOMContentLoaded', function () { compile(document.body); });
})();
</script>
</body></html>"""


class _Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path: str) -> str:
        resolved = super().translate_path(path)
        if resolved.endswith(("feedback", "hash", "comment")):
            return resolved + ".html"
        return resolved

    def _send_html(self, html: str) -> None:
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj: dict | list) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        posts = getattr(self.server, "posts", None)
        path = self.path.split("?", 1)[0]
        if path == "/search":
            query = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            reflected = query.get("search", [""])[0]
            self._send_html(REFLECTED_DOM.replace("@@SEARCH@@", reflected))
            return
        if path == "/product":
            self._send_html(SEARCH_JSON_PAGE)
            return
        if path == "/searchResults":
            query = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            reflected = query.get("search", [""])[0]
            body = '{"searchTerm":"' + reflected + '","results":"0 results"}'
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/angular":
            query = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            reflected = query.get("search", [""])[0]
            self._send_html(ANGULAR_TEMPLATE.replace("@@SEARCH@@", reflected))
            return
        if posts is not None and path in ("/comment", "/post/comment"):
            self._send_html(COMMENT_FORM)
            return
        if posts is not None and path.startswith("/post/"):
            try:
                idx = int(path.rsplit("/", 1)[1])
                post = posts[idx]
            except (ValueError, IndexError):
                self.send_error(404)
                return
            self._send_html(POST_VIEW.format(num=idx, **post))
            return
        super().do_GET()

    def do_POST(self) -> None:
        posts = getattr(self.server, "posts", None)
        if posts is None or not self.path.startswith("/post/comment"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        fields = {
            k: v[0]
            for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()
        }
        posts.append({
            "name":    fields.get("name", "anonymous"),
            "comment": fields.get("comment", ""),
            "website": fields.get("website", ""),
        })
        # Post/Redirect/Get — the browser lands on the per-post view.
        self.send_response(303)
        self.send_header("Location", f"/post/{len(posts) - 1}")
        self.end_headers()

    def log_message(self, *args) -> None:  # keep test output clean
        return


class LabServer:
    """Serves the fixture pages on a random localhost port."""

    def __init__(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        (self.tmp / "index.html").write_text(HOME, encoding="utf-8")
        (self.tmp / "feedback.html").write_text(FEEDBACK, encoding="utf-8")
        (self.tmp / "hash.html").write_text(HASH, encoding="utf-8")
        (self.tmp / "comment.html").write_text(COMMENT_FORM, encoding="utf-8")
        handler = functools.partial(_Handler, directory=str(self.tmp))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        # Comment storage for the stored-XSS flow.
        self.httpd.posts = []
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def feedback_url(self) -> str:
        return self.base + "/feedback"

    @property
    def hash_url(self) -> str:
        return self.base + "/hash"

    @property
    def comment_url(self) -> str:
        return self.base + "/comment"

    @property
    def comment_action(self) -> str:
        return self.base + "/post/comment"

    @property
    def angular_url(self) -> str:
        return self.base + "/angular"

    @property
    def search_url(self) -> str:
        return self.base + "/search"

    @property
    def product_url(self) -> str:
        return self.base + "/product"

    @property
    def search_results_url(self) -> str:
        return self.base + "/searchResults"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

