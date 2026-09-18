/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv

import java.io.File

import net.nmoncho.sbt.osv.api.v1.Client
import net.nmoncho.sbt.osv.api.v1.StubOsvServer
import net.nmoncho.sbt.osv.settings.EngineSettings
import net.nmoncho.sbt.osv.settings.ReportGenerator
import net.nmoncho.sbt.osv.storage.ConnectionProvider
import net.nmoncho.sbt.osv.storage.VulnerabilityRepository
import sbt.Logger

/** Deterministic, offline end-to-end tests exercising the real `Client`, `Engine`,
  * H2 cache and report generation against a stub OSV API.
  */
class IntegrationSpec extends munit.FunSuite {

  implicit val log: Logger = Logger.Null

  private def engine(baseUrl: String): Engine.Default =
    new Engine.Default(
      EngineSettings.Default,
      Client(baseUrl),
      ConnectionProvider.h2InMemory(),
      connection => {
        ConnectionProvider.createSchema(connection)
        VulnerabilityRepository.jdbc(connection)
      }
    )

  private val knownVulnJson =
    """{"id":"GHSA-known","schema_version":"1.6.0","summary":"Known issue","details":"detail",""" +
      """"affected":[],"severity":[{"type":"CVSS_V3",""" +
      """"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"""

  test("end-to-end: a known vulnerable dependency is detected and appears in the report") {
    val handler: (String, String) => (Int, String) = (path, _) =>
      if (path == "/v1/querybatch")
        (200, """{"results":[{"vulns":[{"id":"GHSA-known","modified":"2020-01-01T00:00:00Z"}]}]}""")
      else if (path == "/v1/query")
        (200, s"""{"vulns":[$knownVulnJson]}""")
      else (404, "{}")

    StubOsvServer.withServer(handler) { server =>
      val e = engine(server.baseUrl)
      try {
        val dep = Dependency("org.example", "vulnerable", "1.0.0", new File("vulnerable-1.0.0.jar"))
        val result = e.analyzeDependencies(0.0, Set(dep), Set.empty)

        val found = result.vulnerabilities.getOrElse(dep, Set.empty)
        assertEquals(found.map(_.id), Set("GHSA-known"))
        assert(
          found.exists(_.scores.exists(_.score >= 9.0)),
          "the advisory should carry its CVSS score"
        )

        val json = ReportGenerator.JSON.generate(result.vulnerabilities)
        assert(json.contains("GHSA-known"), s"report should contain the advisory:\n$json")
      } finally e.close()
    }
  }

  test("end-to-end: a clean dependency yields no findings (true negative)") {
    val handler: (String, String) => (Int, String) = (path, _) =>
      if (path == "/v1/querybatch") (200, """{"results":[{}]}""") // no vulnerabilities
      else (404, "{}")

    StubOsvServer.withServer(handler) { server =>
      val e = engine(server.baseUrl)
      try {
        val dep    = Dependency("org.example", "clean", "1.0.0", new File("clean-1.0.0.jar"))
        val result = e.analyzeDependencies(0.0, Set(dep), Set.empty)

        assert(
          result.vulnerabilities.getOrElse(dep, Set.empty).isEmpty,
          "a clean dependency must produce no findings"
        )
      } finally e.close()
    }
  }
}
