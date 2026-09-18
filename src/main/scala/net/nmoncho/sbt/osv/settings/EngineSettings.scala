/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.settings

import java.io.File
import java.time.Duration

/** Engine Settings
  *
  * @param baseUrl base url for OSV API
  * @param cacheEviction how long to wait until going to the API again for a given query
  * @param dataDirectory where to place the data (eg. the database)
  * @param analysisTimeout maximum wall-clock time allowed for the whole analysis (`None` = unbounded)
  * @param connectionTimeout HTTP connection timeout for OSV API calls (`None` = library default)
  * @param connectionReadTimeout HTTP read timeout for OSV API calls (`None` = library default)
  */
case class EngineSettings(
    baseUrl: String,
    cacheEviction: Duration,
    dataDirectory: Option[File],
    analysisTimeout: Option[Duration]       = None,
    connectionTimeout: Option[Duration]     = None,
    connectionReadTimeout: Option[Duration] = None
) {

  /** Returns a copy with the given timeouts applied. A provided value wins over the
    * one already held (which lets the standalone `osv*Timeout` settings override
    * whatever is carried in `osvEngineSettings`).
    */
  def withTimeouts(
      analysis: Option[Duration],
      connection: Option[Duration],
      connectionRead: Option[Duration]
  ): EngineSettings =
    copy(
      analysisTimeout       = analysis.orElse(analysisTimeout),
      connectionTimeout     = connection.orElse(connectionTimeout),
      connectionReadTimeout = connectionRead.orElse(connectionReadTimeout)
    )

  def toPrettyString(): String =
    s"""EngineSettings:
       |  baseUrl: $baseUrl
       |  cacheEviction: ${cacheEviction.toString}
       |  dataDirectory: ${dataDirectory
        .getOrElse(EngineSettings.findDataDirectory())
        .getAbsolutePath}
       |  analysisTimeout: ${analysisTimeout.map(_.toString).getOrElse("unbounded")}
       |  connectionTimeout: ${connectionTimeout.map(_.toString).getOrElse("default")}
       |  connectionReadTimeout: ${connectionReadTimeout.map(_.toString).getOrElse("default")}
       |""".stripMargin

}

object EngineSettings {

  /** Default settings for Engine */
  final val Default: EngineSettings =
    EngineSettings(
      baseUrl       = "https://api.osv.dev",
      cacheEviction = Duration.ofDays(1),
      dataDirectory = None
    )

  /** Finds the default data directory based on where the JAR of this library is located
    *
    * This will unify the db for all projects using the plugin on a local machine
    *
    * @return data directory
    */
  def findDataDirectory(): File = {
    def inner(f: Option[File]): File = f match {
      case Some(value) =>
        if (value.exists() && value.isDirectory) value
        else inner(Option(value.getParentFile))

      case None =>
        throw new IllegalStateException("Couldn't find proper place where to put database file")
    }

    inner(
      Option(
        new File(
          classOf[EngineSettings].getResource("EngineSettings.class").getFile.replace("file:", "")
        )
      )
    )
  }
}
