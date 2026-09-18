/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv

import java.io.File
import java.sql.Connection

import net.nmoncho.sbt.osv.api.OsvVulnerability
import net.nmoncho.sbt.osv.api.v1.Client
import net.nmoncho.sbt.osv.api.v1.V1BatchVulnerabilityList
import net.nmoncho.sbt.osv.settings.EngineSettings
import net.nmoncho.sbt.osv.storage.ConnectionProvider
import net.nmoncho.sbt.osv.storage.VulnerabilityRepository
import org.mockito.ArgumentMatchers._
import org.mockito.Mockito._
import sbt.Logger

class EngineSpec extends munit.FunSuite {

  implicit val log: Logger = Logger.Null

  test("queries not found in the cache should be queried against the client") {
    val client       = mock(classOf[Client])
    val dbProvider   = ConnectionProvider.h2InMemory()
    val repo         = mock(classOf[VulnerabilityRepository])
    val repoProvider = (_: Connection) => repo

    when(repo.findCached(any(), any())).thenReturn(None)
    when(client.queryBatch(any())(any())).thenReturn(Right(V1BatchVulnerabilityList(None)))

    val engine = new Engine.Default(
      EngineSettings.Default,
      client,
      dbProvider,
      repoProvider
    )

    val dep = Dependency("org.foo", "bar", "1.0.0", new File("foo.jar"))

    engine.analyzeDependencies(0.0, Set(dep), Set.empty)

    verify(repo, times(1)).findCached(any(), any())
    verify(client, times(1)).queryBatch(any())(any())
  }

  test("queries found in the cache shouldn't be queried against the client") {
    val client       = mock(classOf[Client])
    val dbProvider   = ConnectionProvider.h2InMemory()
    val repo         = mock(classOf[VulnerabilityRepository])
    val repoProvider = (_: Connection) => repo

    // Returning empty seq, which means no vulnerabilities for this dependency
    when(repo.findCached(any(), any())).thenReturn(Some(Seq.empty))

    val engine = new Engine.Default(
      EngineSettings.Default,
      client,
      dbProvider,
      repoProvider
    )

    val dep = Dependency("org.foo", "bar", "1.0.0", new File("foo.jar"))

    engine.analyzeDependencies(0.0, Set(dep), Set.empty)

    verifyNoInteractions(client)
  }

  // -------------------------------------------------------------------------
  // Suppression matching: match by primary id AND aliases
  // -------------------------------------------------------------------------

  private val suppressionDep = Dependency("org.foo", "bar", "1.0.0", new File("foo.jar"))

  private def osvVuln(id: String, aliases: String*): OsvVulnerability =
    OsvVulnerability(
      id            = id,
      schemaVersion = "1.0.0",
      summary       = "",
      details       = "",
      affected      = Seq.empty,
      aliases       = if (aliases.isEmpty) None else Some(aliases.toSeq)
    )

  /** Builds an engine whose cache returns the given advisories for any query, so
    * the client is never contacted and only the suppression logic is exercised.
    */
  private def engineReturning(vulns: OsvVulnerability*): Engine.Default = {
    val client = mock(classOf[Client])
    val repo   = mock(classOf[VulnerabilityRepository])
    when(repo.findCached(any(), any())).thenReturn(Some(vulns.toSeq))
    new Engine.Default(
      EngineSettings.Default,
      client,
      ConnectionProvider.h2InMemory(),
      (_: Connection) => repo
    )
  }

  private def rule(name: String): SuppressionRule = SuppressionRule(name, "", "")

  test("a CVE-named suppression suppresses a GHSA-primary advisory via its alias") {
    val engine = engineReturning(osvVuln("GHSA-aaaa-bbbb-cccc", "CVE-2022-1234"))

    val result = engine.analyzeDependencies(
      0.0,
      Set(suppressionDep),
      Set(rule("CVE-2022-1234"))
    )

    assert(
      result.vulnerabilities.getOrElse(suppressionDep, Set.empty).isEmpty,
      "the advisory should have been suppressed"
    )
    assertEquals(result.suppressed.map(_.id), Set("GHSA-aaaa-bbbb-cccc"))
    assertEquals(result.unusedSuppressions, Set.empty[SuppressionRule])
  }

  test("a GHSA-named suppression suppresses a CVE-primary advisory via its alias") {
    val engine = engineReturning(osvVuln("CVE-2022-1234", "GHSA-aaaa-bbbb-cccc"))

    val result = engine.analyzeDependencies(
      0.0,
      Set(suppressionDep),
      Set(rule("GHSA-aaaa-bbbb-cccc"))
    )

    assert(result.vulnerabilities.getOrElse(suppressionDep, Set.empty).isEmpty)
    assertEquals(result.suppressed.map(_.id), Set("CVE-2022-1234"))
    assertEquals(result.unusedSuppressions, Set.empty[SuppressionRule])
  }

  test("an exact primary-id suppression still works") {
    val engine = engineReturning(osvVuln("CVE-2022-1234"))

    val result = engine.analyzeDependencies(
      0.0,
      Set(suppressionDep),
      Set(rule("CVE-2022-1234"))
    )

    assert(result.vulnerabilities.getOrElse(suppressionDep, Set.empty).isEmpty)
    assertEquals(result.suppressed.map(_.id), Set("CVE-2022-1234"))
  }

  test("a non-matching suppression leaves the advisory and is reported as unused") {
    val ruleThatMatchesNothing = rule("CVE-9999-0000")
    val engine                 = engineReturning(osvVuln("GHSA-aaaa-bbbb-cccc", "CVE-2022-1234"))

    val result = engine.analyzeDependencies(
      0.0,
      Set(suppressionDep),
      Set(ruleThatMatchesNothing)
    )

    assertEquals(
      result.vulnerabilities.getOrElse(suppressionDep, Set.empty).map(_.id),
      Set("GHSA-aaaa-bbbb-cccc")
    )
    assert(result.suppressed.isEmpty)
    assertEquals(result.unusedSuppressions, Set(ruleThatMatchesNothing))
  }

}
