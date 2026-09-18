/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv
package tasks

import java.io.File

import scala.collection.mutable.ListBuffer

import net.nmoncho.sbt.osv.api.OsvVulnerability
import net.nmoncho.sbt.osv.settings.ReportGenerator
import net.nmoncho.sbt.osv.settings.SummaryReport
import sbt.util.Level

class ReportFindingsSpec extends munit.FunSuite {

  /** Captures everything logged so the console output can be asserted. */
  private class RecordingLogger extends sbt.util.Logger {
    val messages: ListBuffer[String] = ListBuffer.empty[String]

    override def log(level: Level.Value, message: => String): Unit = { messages += message; () }
    override def success(message: => String): Unit                 = { messages += message; () }
    override def trace(t: => Throwable): Unit                      = ()
  }

  private val dep = Dependency("org", "artifact", "1.0", new File("artifact-1.0.jar"))

  private def osvSource(id: String): OsvVulnerability =
    OsvVulnerability(
      id            = id,
      schemaVersion = "1.0.0",
      summary       = "",
      details       = "",
      affected      = Seq.empty
    )

  private def vuln(id: String, scores: Vulnerability.Score*): Vulnerability =
    Vulnerability(id, Set.empty, scores.toSet, Vulnerability.FixedStatus.Unknown, osvSource(id))

  private def stubEngine(result: Engine.ScanResult): Engine = new Engine {
    override def analyzeDependencies(
        failCvssScore: Double,
        dependencies: Set[Dependency],
        suppressions: Set[SuppressionRule]
    )(implicit log: sbt.Logger): Engine.ScanResult = result

    override def close(): Unit = ()

    override def writeReports(projectName: String, outputDir: File, report: String): Unit = ()
  }

  private def run(
      result: Engine.ScanResult,
      failCvssScore: Double,
      reportFormats: Seq[ReportGenerator] = Seq.empty
  )(implicit log: sbt.Logger): Engine.ScanResult =
    analyzeProject(
      projectName      = "proj",
      engine           = stubEngine(result),
      dependencies     = Set.empty,
      suppressionRules = Set.empty,
      failCvssScore    = failCvssScore,
      outputDir        = new File("target"),
      reportFormats    = reportFormats,
      summaryReport    = SummaryReport.DependencyCheck
    )

  test("no vulnerabilities logs an explicit 'none found' message") {
    implicit val log: RecordingLogger = new RecordingLogger

    run(Engine.ScanResult(Map(dep -> Set.empty[Vulnerability]), Set.empty, Set.empty), 11.0)

    assert(
      log.messages.exists(_.contains("No known vulnerabilities found")),
      log.messages.mkString("\n")
    )
  }

  test("findings below the threshold are reported as found-but-not-exceeding, without failing") {
    implicit val log: RecordingLogger = new RecordingLogger

    val result = Engine.ScanResult(
      Map(dep -> Set(vuln("CVE-1", Vulnerability.Score("CVSS_V3", "", 5.0)))),
      Set.empty,
      Set.empty
    )

    run(result, 11.0) // must not throw

    val text = log.messages.mkString("\n")
    assert(text.contains("Found [1] known vulnerabilities"), text)
    assert(text.contains("none exceed the CVSS threshold"), text)
  }

  test("findings above the threshold are reported and fail the build") {
    implicit val log: RecordingLogger = new RecordingLogger

    val result = Engine.ScanResult(
      Map(dep -> Set(vuln("CVE-2", Vulnerability.Score("CVSS_V3", "", 9.0)))),
      Set.empty,
      Set.empty
    )

    intercept[VulnerabilityFoundException] {
      run(result, 5.0)
    }

    val text = log.messages.mkString("\n")
    assert(text.contains("Found [1] known vulnerabilities"), text)
    assert(text.contains("which exceed the CVSS threshold"), text)
  }

  test("the report file path is logged, not just the directory") {
    implicit val log: RecordingLogger = new RecordingLogger

    run(
      Engine.ScanResult(Map(dep -> Set.empty[Vulnerability]), Set.empty, Set.empty),
      11.0,
      Seq(ReportGenerator.HTML)
    )

    assert(log.messages.exists(_.contains("osv-report.html")), log.messages.mkString("\n"))
  }

}
