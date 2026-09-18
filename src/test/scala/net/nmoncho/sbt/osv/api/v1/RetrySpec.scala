/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.api.v1

class RetrySpec extends munit.FunSuite {

  import Retry.Attempt

  test("returns immediately on a Done result without sleeping") {
    var sleeps = 0
    var calls  = 0

    val out = Retry.retrying(3, _ => sleeps += 1) { calls += 1; Attempt.Done("ok") }

    assertEquals(out, "ok")
    assertEquals(calls, 1)
    assertEquals(sleeps, 0)
  }

  test("retries transient results until one succeeds") {
    var sleeps = 0
    var calls  = 0

    val out = Retry.retrying(5, _ => sleeps += 1) {
      calls += 1
      if (calls < 3) Attempt.Retryable("transient") else Attempt.Done("ok")
    }

    assertEquals(out, "ok")
    assertEquals(calls, 3)
    assertEquals(sleeps, 2)
  }

  test("gives up after maxAttempts and returns the last retryable value") {
    var sleeps = 0
    var calls  = 0

    val out = Retry.retrying(3, _ => sleeps += 1) { calls += 1; Attempt.Retryable(s"fail-$calls") }

    assertEquals(out, "fail-3")
    assertEquals(calls, 3)
    assertEquals(sleeps, 2)
  }

  test("maxAttempts = 1 never retries") {
    var sleeps = 0
    var calls  = 0

    val out = Retry.retrying(1, _ => sleeps += 1) { calls += 1; Attempt.Retryable("once") }

    assertEquals(out, "once")
    assertEquals(calls, 1)
    assertEquals(sleeps, 0)
  }

  test("rejects maxAttempts < 1") {
    intercept[IllegalArgumentException] {
      Retry.retrying(0, _ => ())(Attempt.Done("x"))
    }
  }

}
