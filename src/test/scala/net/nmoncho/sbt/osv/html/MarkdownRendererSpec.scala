/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.html

class MarkdownRendererSpec extends munit.FunSuite {

  test("renders CommonMark formatting to HTML") {
    val html = MarkdownRenderer.render("This is **bold** and _italic_.").body
    assert(html.contains("<strong>bold</strong>"), html)
    assert(html.contains("<em>italic</em>"), html)
  }

  test("renders a markdown link") {
    val html = MarkdownRenderer.render("See [the advisory](https://example.com/advisory).").body
    assert(html.contains("href=\"https://example.com/advisory\""), html)
  }

  test("renders lists") {
    val html = MarkdownRenderer.render("- one\n- two").body
    assert(html.contains("<ul>"), html)
    assert(html.contains("<li>one</li>"), html)
  }

  test("escapes raw HTML embedded in the source (no injection)") {
    val html = MarkdownRenderer.render("hi <script>alert('xss')</script>").body
    assert(!html.contains("<script>"), html)
    assert(html.contains("&lt;script&gt;"), html)
  }

  test("sanitizes dangerous link URLs") {
    val html = MarkdownRenderer.render("[click](javascript:alert(1))").body
    assert(!html.contains("javascript:"), html)
  }

  test("empty or null input yields empty HTML") {
    assertEquals(MarkdownRenderer.render("").body, "")
    assertEquals(MarkdownRenderer.render(null).body, "")
  }

}
