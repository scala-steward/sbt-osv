/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.settings

import net.nmoncho.sbt.osv.Dependency
import net.nmoncho.sbt.osv.Vulnerability
import net.nmoncho.sbt.osv.api.OsvVulnerability

sealed trait ReportGenerator {

  /** Report filename based on the project name
    */
  def reportName(projectName: String): String

  /** Generates a vulnerability report based on findings
    *
    * @param result the found vulnerabilities for each dependency
    * @return the report as a string
    */
  def generate(result: Map[Dependency, Set[Vulnerability]]): String
}

object ReportGenerator {

  case object HTML extends ReportGenerator {

    override def reportName(projectName: String): String = "osv-report.html"

    override def generate(result: Map[Dependency, Set[Vulnerability]]): String = {
      val model: Map[Dependency, Set[OsvVulnerability]] = result.map { case (d, vs) =>
        d -> vs.map(_.source)
      }

      net.nmoncho.sbt.osv.html.html.report(model).toString()
    }
  }

  /** Machine-readable JSON report, suitable for CI pipelines and downstream tooling. */
  case object JSON extends ReportGenerator {

    override def reportName(projectName: String): String = "osv-report.json"

    override def generate(result: Map[Dependency, Set[Vulnerability]]): String = {
      val dependencies = result.toSeq
        .sortBy(_._1.coordinates)
        .map { case (dependency, vulnerabilities) =>
          ujson.Obj(
            "coordinates" -> ujson.Str(dependency.coordinates),
            "groupId" -> ujson.Str(dependency.groupId),
            "artifactId" -> ujson.Str(dependency.artifactId),
            "version" -> ujson.Str(dependency.revision),
            "purl" -> ujson.Str(dependency.purl),
            "file" -> ujson.Str(dependency.file.getName),
            "vulnerabilities" -> ujson.Arr(
              vulnerabilities.toSeq.sortBy(_.id).map { vulnerability =>
                ujson.Obj(
                  "id" -> ujson.Str(vulnerability.id),
                  "aliases" -> ujson.Arr(vulnerability.aliases.toSeq.sorted.map(ujson.Str(_)): _*),
                  "summary" -> ujson.Str(vulnerability.source.summary),
                  "scores" -> ujson.Arr(
                    vulnerability.scores.toSeq.sortBy(_.name).map { score =>
                      ujson.Obj(
                        "type" -> ujson.Str(score.name),
                        "vector" -> ujson.Str(score.vector),
                        "score" -> ujson.Num(score.score),
                        "severity" -> ujson.Str(Vulnerability.Score.scoreSeverity(score.vector))
                      )
                    }: _*
                  ),
                  "references" -> ujson.Arr(
                    vulnerability.source.references
                      .getOrElse(Seq.empty)
                      .map(reference => ujson.Str(reference.url)): _*
                  )
                )
              }: _*
            )
          )
        }

      ujson.write(ujson.Obj("dependencies" -> ujson.Arr(dependencies: _*)), indent = 2)
    }
  }

}
