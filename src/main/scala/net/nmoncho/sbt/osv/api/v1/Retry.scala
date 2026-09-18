/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.api.v1

import scala.annotation.tailrec

/** Tiny retry helper used to make transient OSV API failures (network blips, HTTP
  * 429, 5xx) survivable instead of aborting the scan on the first hiccup.
  *
  * It is deliberately decoupled from HTTP so it can be unit-tested without a server:
  * each attempt classifies its own outcome as [[Attempt.Done]] (stop) or
  * [[Attempt.Retryable]] (retry while attempts remain).
  */
private[v1] object Retry {

  sealed trait Attempt[+A] {
    def value: A
  }

  object Attempt {
    final case class Done[A](value: A)      extends Attempt[A]
    final case class Retryable[A](value: A) extends Attempt[A]
  }

  /** Runs `op` up to `maxAttempts` times.
    *
    * Retries only while an attempt reports `Retryable` and attempts remain, calling
    * `sleep(attemptIndex)` before each retry. Returns the value of the last attempt,
    * whether it stopped with `Done` or exhausted the retries on a `Retryable`.
    *
    * @param maxAttempts total number of attempts (must be >= 1)
    * @param sleep       back-off invoked with the zero-based index of the attempt just made
    * @param op          the (re-runnable) operation to attempt
    */
  def retrying[A](maxAttempts: Int, sleep: Int => Unit)(op: => Attempt[A]): A = {
    require(maxAttempts >= 1, "maxAttempts must be >= 1")

    @tailrec def loop(n: Int): A =
      op match {
        case Attempt.Done(value) =>
          value

        case Attempt.Retryable(value) =>
          if (n + 1 < maxAttempts) {
            sleep(n)
            loop(n + 1)
          } else {
            value
          }
      }

    loop(0)
  }
}
