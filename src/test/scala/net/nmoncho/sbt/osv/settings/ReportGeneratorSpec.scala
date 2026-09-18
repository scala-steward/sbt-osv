/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.settings

import java.io.File

import scala.io.Source
import scala.util.Using

import net.nmoncho.sbt.osv.Dependency
import net.nmoncho.sbt.osv.TestUtils
import net.nmoncho.sbt.osv.Vulnerability
import net.nmoncho.sbt.osv.api.OsvVulnerability
import net.nmoncho.sbt.osv.api.v1.V1VulnerabilityList
import sbt.Logger

class ReportGeneratorSpec extends munit.FunSuite with TestUtils {

  implicit val log: Logger = Logger.Null

  test("generate a HTML report") {
    val result = readJsonQueries()

    val model: Map[Dependency, Set[OsvVulnerability]] = result.map { case (d, vs) =>
      d -> vs.map(_.source)
    }

    sbt.IO.write(
      new File("report.html"),
      net.nmoncho.sbt.osv.html.html.report(model).toString()
    )
  }

  test("JSON report name is osv-report.json") {
    assertEquals(ReportGenerator.JSON.reportName("anything"), "osv-report.json")
  }

  test("JSON report is valid JSON with the expected structure") {
    val dep           = Dependency("org.example", "lib", "1.2.3", new File("lib-1.2.3.jar"))
    val vulnerability = Vulnerability(
      id      = "GHSA-xxxx",
      aliases = Set("CVE-2022-1"),
      scores  = Set(
        Vulnerability.Score("CVSS_V3", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.6)
      ),
      fixed  = Vulnerability.FixedStatus.Unknown,
      source = OsvVulnerability("GHSA-xxxx", "1.0.0", "a summary", "", Seq.empty)
    )

    val json   = ReportGenerator.JSON.generate(Map(dep -> Set(vulnerability)))
    val parsed = ujson.read(json)

    val d = parsed("dependencies")(0)
    assertEquals(d("coordinates").str, "org.example:lib:1.2.3")
    assertEquals(d("groupId").str, "org.example")

    val v = d("vulnerabilities")(0)
    assertEquals(v("id").str, "GHSA-xxxx")
    assertEquals(v("aliases")(0).str, "CVE-2022-1")
    assertEquals(v("summary").str, "a summary")
    assertEquals(v("scores")(0)("score").num, 7.6)
  }

  test("JSON report renders an empty dependency set as an empty array") {
    val json   = ReportGenerator.JSON.generate(Map.empty)
    val parsed = ujson.read(json)
    assertEquals(parsed("dependencies").arr.length, 0)
  }

  @SuppressWarnings(Array("DisableSyntax.noValPatterns"))
  private def readJsonQueries(): Map[Dependency, Set[Vulnerability]] = {
    import net.nmoncho.sbt.osv.api.SnakeCaseConfig.*

    val folder = new File("src/test/resources/queries")
    folder
      .listFiles()
      .map { f =>
        val List(org, art, ver) = f.getName.replace(".json", "").split("_").toList
        val d                   = Dependency(org, art, ver, f)

        val jsonText = Using(Source.fromFile(f)) { x =>
          x.getLines().mkString("\n")
        }.get

        d -> read[V1VulnerabilityList](jsonText).vulnerabilities()
      }
      .toMap
  }
}
