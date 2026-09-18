/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.settings

import java.time.Duration

class EngineSettingsSpec extends munit.FunSuite {

  private val base = EngineSettings.Default

  test("withTimeouts applies provided timeouts onto settings that have none") {
    val out = base.withTimeouts(
      analysis       = Some(Duration.ofSeconds(30)),
      connection     = Some(Duration.ofSeconds(5)),
      connectionRead = Some(Duration.ofSeconds(10))
    )

    assertEquals(out.analysisTimeout, Some(Duration.ofSeconds(30)))
    assertEquals(out.connectionTimeout, Some(Duration.ofSeconds(5)))
    assertEquals(out.connectionReadTimeout, Some(Duration.ofSeconds(10)))
  }

  test("withTimeouts keeps existing timeouts when none are provided") {
    val existing = base.copy(
      analysisTimeout       = Some(Duration.ofSeconds(1)),
      connectionTimeout     = Some(Duration.ofSeconds(2)),
      connectionReadTimeout = Some(Duration.ofSeconds(3))
    )

    val out = existing.withTimeouts(None, None, None)

    assertEquals(out.analysisTimeout, Some(Duration.ofSeconds(1)))
    assertEquals(out.connectionTimeout, Some(Duration.ofSeconds(2)))
    assertEquals(out.connectionReadTimeout, Some(Duration.ofSeconds(3)))
  }

  test("withTimeouts lets a provided value override an existing one") {
    val existing = base.copy(analysisTimeout = Some(Duration.ofSeconds(1)))

    val out = existing.withTimeouts(Some(Duration.ofSeconds(99)), None, None)

    assertEquals(out.analysisTimeout, Some(Duration.ofSeconds(99)))
  }

}
