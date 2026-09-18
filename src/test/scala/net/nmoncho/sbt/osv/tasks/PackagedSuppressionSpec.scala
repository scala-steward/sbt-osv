/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv
package tasks

import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

import net.nmoncho.sbt.osv.settings.SuppressionSettings
import net.nmoncho.sbt.osv.settings.SuppressionSettings.PackagedFilter
import sbt.Logger
import sbt.internal.util.Attributed

class PackagedSuppressionSpec extends munit.FunSuite {

  implicit val log: Logger = Logger.Null

  private def tempFile(suffix: String): File = {
    val f = File.createTempFile("osv-test", suffix)
    f.deleteOnExit()
    f
  }

  /** Builds a JAR (zip) containing a single entry, e.g. a packaged `.osvignore`. */
  private def jarWith(entryName: String, content: String): File = {
    val jar = tempFile(".jar")
    val zos = new ZipOutputStream(new FileOutputStream(jar))
    try {
      zos.putNextEntry(new ZipEntry(entryName))
      zos.write(content.getBytes(UTF_8))
      zos.closeEntry()
    } finally zos.close()
    jar
  }

  private val missingFile = new File("target/does-not-exist.osvignore")

  test("writeExportSuppressions writes rules that parse back, stamping a blank source") {
    val out      = tempFile(".osvignore")
    val settings = SuppressionSettings(
      file            = missingFile,
      suppressions    = Set(SuppressionRule("CVE-2021-1234", "not applicable", "")),
      packagedEnabled = true,
      packagedFilter  = PackagedFilter.WhitelistAll
    )

    assert(GenerateSuppressions.writeExportSuppressions(out, settings, "my-lib"))

    val parsed = SuppressionParser.parse(out)
    assertEquals(parsed.map(_.name), Set("CVE-2021-1234"))
    assert(parsed.exists(_.source == "my-lib"), s"blank source should be stamped: $parsed")
  }

  test("collectImportedPackagedSuppressions reads rules from a dependency JAR") {
    val jar      = jarWith(".osvignore", "# packaged\nCVE-2020-9999\n")
    val settings = SuppressionSettings(
      file            = missingFile,
      suppressions    = Set.empty,
      packagedEnabled = true,
      packagedFilter  = PackagedFilter.WhitelistAll
    )

    val rules = GenerateSuppressions.collectImportedPackagedSuppressions(
      settings,
      Set(Attributed.blank(jar))
    )

    assertEquals(rules.map(_.name).toSet, Set("CVE-2020-9999"))
  }

  test("collectImportedPackagedSuppressions returns nothing when packaging is disabled") {
    val jar      = jarWith(".osvignore", "CVE-2020-9999\n")
    val settings = SuppressionSettings(
      file            = missingFile,
      suppressions    = Set.empty,
      packagedEnabled = false,
      packagedFilter  = PackagedFilter.WhitelistAll
    )

    val rules =
      GenerateSuppressions.collectImportedPackagedSuppressions(settings, Set(Attributed.blank(jar)))

    assert(rules.isEmpty)
  }

  test("round-trip: export rules, package them into a JAR, then read them back") {
    val exported       = tempFile(".osvignore")
    val exportSettings = SuppressionSettings(
      file            = missingFile,
      suppressions    = Set(SuppressionRule("GHSA-aaaa-bbbb-cccc", "reviewed", "")),
      packagedEnabled = true,
      packagedFilter  = PackagedFilter.WhitelistAll
    )
    assert(GenerateSuppressions.writeExportSuppressions(exported, exportSettings, "producer-lib"))

    val jar            = jarWith(".osvignore", sbt.IO.read(exported))
    val importSettings = SuppressionSettings(
      file            = missingFile,
      suppressions    = Set.empty,
      packagedEnabled = true,
      packagedFilter  = PackagedFilter.WhitelistAll
    )

    val rules =
      GenerateSuppressions.collectImportedPackagedSuppressions(
        importSettings,
        Set(Attributed.blank(jar))
      )

    assertEquals(rules.map(_.name).toSet, Set("GHSA-aaaa-bbbb-cccc"))
    assert(
      rules.exists(_.source == "producer-lib"),
      s"source should survive the round-trip: $rules"
    )
  }
}
