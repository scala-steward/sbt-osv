/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.html

import org.commonmark.parser.Parser
import org.commonmark.renderer.html.HtmlRenderer
import play.twirl.api.Html

/** Renders OSV advisory `details` (CommonMark) into HTML for the report.
  *
  * The advisory text comes from an external database and is therefore untrusted, so
  * the renderer is hardened: raw HTML embedded in the source is escaped rather than
  * passed through, and link/image URLs are sanitized (disallowed schemes such as
  * `javascript:` are stripped). Combined with rendering server-side, the report stays
  * self-contained and cannot be used to inject active content.
  */
object MarkdownRenderer {

  private val parser: Parser = Parser.builder().build()

  private val renderer: HtmlRenderer =
    HtmlRenderer
      .builder()
      .escapeHtml(true)
      .sanitizeUrls(true)
      .build()

  /** Renders CommonMark `markdown` to sanitized HTML, wrapped as Twirl [[Html]] so the
    * template emits it unescaped. Empty or `null` input yields empty HTML.
    */
  def render(markdown: String): Html =
    if (markdown == null || markdown.isEmpty) Html("")
    else Html(renderer.render(parser.parse(markdown)))
}
