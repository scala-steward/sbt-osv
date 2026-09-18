/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.tasks

import net.nmoncho.sbt.osv.Keys.osvSkip
import net.nmoncho.sbt.osv.SuppressionRule
import sbt.Keys._
import sbt._
import sbt.plugins.JvmPlugin

/** Lists the suppression rules in effect for the scan, whether defined in the project
  * definition (ie. `build.sbt` or an `.osvignore` file) or imported as packaged
  * suppression rules from dependency JARs.
  *
  * The goal of this task is to make visible to users which suppressions are being
  * applied, since they can come from several sources.
  */
object ListSuppressions {

  def apply(): Def.Initialize[InputTask[Unit]] = Def.inputTaskDyn {
    implicit val log: Logger = streams.value.log

    Def
      .task {
        val rules = projectSelectionParser.parsed match {
          case Some(ProjectSelection.AllProjects) =>
            Seq(name.value -> AllProjectsScan.suppressions().tag(NonParallel).value)

          case Some(ProjectSelection.PerProject) | _ =>
            suppressionRulesFilter.tag(NonParallel).value.sortBy { case (name, _) => name }
        }

        rules.foreach { case (name, rules) =>
          if (rules.nonEmpty) {
            log.info(s"Suppression rules added for [$name]")
            rules.foreach(rule => log.info(s"\t$rule"))
            log.info("\n\n")
          } else {
            log.info(s"No suppression rules added for [$name]")
            log.info("\n\n")
          }
        }
      }
      .tag(NonParallel)
  }

  private lazy val suppressionRulesFilter = Def.settingDyn {
    suppressionRulesTask
      .all(ScopeFilter(inAggregates(thisProjectRef.value), inConfigurations(Compile)))
  }

  private lazy val suppressionRulesTask: Def.Initialize[Task[(String, Set[SuppressionRule])]] =
    Def.taskDyn {
      if (!thisProject.value.autoPlugins.contains(JvmPlugin) || (osvSkip ?? false).value)
        Def.task(name.value -> Set.empty)
      else
        Def.task(name.value -> GenerateSuppressions.forProject.value)
    }
}
