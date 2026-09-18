/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv
package api

import java.time.Duration
import java.time.Instant

import scala.util.control.NonFatal

import requests.Response
import sbt.Logger

package object v1 {

  import SnakeCaseConfig.*

  implicit val instantReadWriter: ReadWriter[Instant] =
    readwriter[String].bimap(_.toString, Instant.parse)

  class Client private (
      baseUrl: String,
      connectTimeout: Option[Duration],
      readTimeout: Option[Duration]
  ) {

    // requests-scala expects timeouts in milliseconds; when unset we keep its own
    // 10s default so behaviour is unchanged unless the user configures a timeout.
    private val connectTimeoutMs: Int = connectTimeout.map(_.toMillis.toInt).getOrElse(10000)
    private val readTimeoutMs: Int    = readTimeout.map(_.toMillis.toInt).getOrElse(10000)

    // Transient OSV API failures (network blips, HTTP 429, 5xx) are retried a few
    // times with a short exponential back-off before the call is reported as failed.
    private val maxAttempts: Int                  = 3
    private def backoff(attempt: Int): Unit       = Thread.sleep(500L * (attempt + 1))
    private def isTransient(status: Int): Boolean = status == 429 || status >= 500

    /** Queries the vulnerabilities for a given package
      *
      * See also <a href="https://google.github.io/osv.dev/post-v1-query/">docs</a>
      *
      * This method handles pagination
      *
      * @param q query to run against API
      * @return either the vulnerability list, which can be empty, or a failed result
      */
    def query(q: V1Query)(implicit log: Logger): Either[RpcStatus, V1VulnerabilityList] = {
      def inner(
          query: V1Query,
          vulns: Vector[OsvVulnerability]
      ): Either[RpcStatus, Vector[OsvVulnerability]] =
        handleResponse[V1VulnerabilityList](
          requests.post(
            url            = s"${baseUrl}/v1/query",
            data           = write(q),
            check          = false,
            connectTimeout = connectTimeoutMs,
            readTimeout    = readTimeoutMs
          )
        ) match {
          // No more vulnerabilities, this case shouldn't happen though
          case Right(V1VulnerabilityList(None, None)) =>
            Right(Vector.empty)

          // No more pages
          case Right(V1VulnerabilityList(values, nextToken)) =>
            val updateVulns = vulns ++ values.getOrElse(Vector.empty)
            nextToken.fold[Either[RpcStatus, Vector[OsvVulnerability]]](Right(updateVulns)) { token =>
              inner(query.copy(pageToken = Some(token)), updateVulns)
            }

          case Left(value) =>
            Left(value)
        }

      inner(q, Vector.empty) match {
        case Right(vulns) => Right(V1VulnerabilityList(Some(vulns)))
        case Left(error) => Left(error)
      }
    }

    /** Queries the vulnerabilities for several packages
      *
      * See also <a href="https://google.github.io/osv.dev/post-v1-querybatch/">docs</a>
      *
      * @param q batch query to run against API
      * @return either the vulnerability list, which can be empty, or a failed result
      */
    def queryBatch(
        q: V1BatchQuery
    )(implicit log: Logger): Either[RpcStatus, V1BatchVulnerabilityList] =
      handleResponse[V1BatchVulnerabilityList](
        requests.post(
          url            = s"${baseUrl}/v1/querybatch",
          data           = write(q),
          check          = false,
          connectTimeout = connectTimeoutMs,
          readTimeout    = readTimeoutMs
        )
      )

    /** Queries vulnerability information for a given ID
      *
      * See also <a href="https://google.github.io/osv.dev/get-v1-vulns/">docs</a>
      *
      * @param id vulnerability ID
      * @return either the vulnerability, or a failed result
      */
    def vulnerability(id: String)(implicit log: Logger): Either[RpcStatus, OsvVulnerability] =
      handleResponse[OsvVulnerability](
        requests.get(
          url            = s"${baseUrl}/v1/vulns/${id}",
          check          = false,
          connectTimeout = connectTimeoutMs,
          readTimeout    = readTimeoutMs
        )
      )

    /** Executes `request` (re-running it on retry) and decodes the response, retrying
      * transient failures. A connectivity failure or an exhausted retry becomes a clean
      * `Left(RpcStatus)` rather than a raw exception propagating out of the client.
      */
    private def handleResponse[A: Reader](
        request: => Response
    )(implicit log: Logger): Either[RpcStatus, A] =
      Retry.retrying(maxAttempts, backoff) {
        try {
          val response = request

          if (response.is2xx) {
            try Retry.Attempt.Done(Right(read[A](response.text())))
            catch {
              case NonFatal(t) =>
                logThrowable(t)
                Retry.Attempt.Done(
                  Left(
                    RpcStatus(
                      Some(response.statusCode),
                      Some(s"Could not parse the OSV API response. Cause: ${t.getMessage}")
                    )
                  )
                )
            }
          } else if (isTransient(response.statusCode)) {
            Retry.Attempt.Retryable(Left(parseError(response)))
          } else {
            Retry.Attempt.Done(Left(parseError(response)))
          }
        } catch {
          case NonFatal(t) =>
            logThrowable(t)
            Retry.Attempt.Retryable(
              Left(RpcStatus(None, Some(s"Could not reach the OSV API. Cause: ${t.getMessage}")))
            )
        }
      }

    private def parseError(response: Response)(implicit log: Logger): RpcStatus =
      try read[RpcStatus](response.text())
      catch {
        case NonFatal(t) =>
          logThrowable(t)
          RpcStatus(
            Some(response.statusCode),
            Some(s"Unexpected OSV API response (HTTP ${response.statusCode})")
          )
      }
  }

  object Client {
    def apply(
        baseUrl: String                  = "https://api.osv.dev",
        connectTimeout: Option[Duration] = None,
        readTimeout: Option[Duration]    = None
    ): Client =
      new Client(
        if (baseUrl.endsWith("/")) baseUrl.substring(0, baseUrl.length - 1) else baseUrl,
        connectTimeout,
        readTimeout
      )
  }
}
