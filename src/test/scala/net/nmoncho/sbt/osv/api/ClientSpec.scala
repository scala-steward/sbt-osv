/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.api

import net.nmoncho.sbt.osv.TestUtils
import net.nmoncho.sbt.osv.api.v1.Client
import net.nmoncho.sbt.osv.api.v1.StubOsvServer
import net.nmoncho.sbt.osv.api.v1.V1BatchQuery
import net.nmoncho.sbt.osv.api.v1.V1Query
import sbt._

class ClientSpec extends munit.FunSuite with TestUtils {
  import TestUtils.moduleIdToDependency

  implicit val log: Logger = Logger.Null

  private def vulnJson(id: String): String =
    s"""{"id":"$id","schema_version":"1.6.0","summary":"summary of $id","details":"details","affected":[]}"""

  test("query parses vulnerabilities from the API") {
    StubOsvServer.withServer((path, _) =>
      if (path == "/v1/query") (200, s"""{"vulns":[${vulnJson("GHSA-x4ff-q6h8-v7gw")}]}""")
      else (404, "{}")
    ) { server =>
      val result = Client(server.baseUrl).query(V1Query.of("org.scala-sbt" % "sbt" % "1.11.7"))

      assert(result.isRight, result.toString)
      val list = result.toOption.get
      assertEquals(list.vulns.map(_.size), Some(1))
      assertEquals(list.vulns.get.head.id, "GHSA-x4ff-q6h8-v7gw")
    }
  }

  test("query follows pagination via next_page_token") {
    var calls = 0
    StubOsvServer.withServer((path, _) =>
      if (path == "/v1/query") {
        calls += 1
        if (calls == 1) (200, s"""{"vulns":[${vulnJson("GHSA-1")}],"next_page_token":"tok"}""")
        else (200, s"""{"vulns":[${vulnJson("GHSA-2")}]}""")
      } else (404, "{}")
    ) { server =>
      val result = Client(server.baseUrl).query(V1Query.of("org" % "art" % "1.0"))

      assert(result.isRight, result.toString)
      assertEquals(result.toOption.get.vulns.map(_.map(_.id)), Some(Vector("GHSA-1", "GHSA-2")))
      assertEquals(calls, 2)
    }
  }

  test("queryBatch parses per-package results") {
    StubOsvServer.withServer((path, _) =>
      if (path == "/v1/querybatch")
        (200, """{"results":[{},{"vulns":[{"id":"GHSA-2","modified":"2020-01-01T00:00:00Z"}]}]}""")
      else (404, "{}")
    ) { server =>
      val result =
        Client(server.baseUrl).queryBatch(V1BatchQuery.of("a" % "a" % "1", "b" % "b" % "1"))

      assert(result.isRight, result.toString)
      val results = result.toOption.get.results.get
      assertEquals(results.size, 2)
      assertEquals(results.head.vulns, None, "first package has no vulnerabilities")
      assert(results(1).vulns.nonEmpty, "second package has vulnerabilities")
    }
  }

  test("a non-2xx response becomes a Left") {
    StubOsvServer.withServer((_, _) => (400, """{"code":3,"message":"bad request"}""")) { server =>
      val result = Client(server.baseUrl).query(V1Query.of("org" % "art" % "1.0"))
      assert(result.isLeft, result.toString)
    }
  }

  test("a transient 503 is retried and then succeeds") {
    var calls = 0
    StubOsvServer.withServer((path, _) =>
      if (path == "/v1/query") {
        calls += 1
        if (calls == 1) (503, "service unavailable")
        else (200, s"""{"vulns":[${vulnJson("GHSA-ok")}]}""")
      } else (404, "{}")
    ) { server =>
      val result = Client(server.baseUrl).query(V1Query.of("org" % "art" % "1.0"))

      assert(result.isRight, result.toString)
      assertEquals(calls, 2, "the transient failure should have been retried")
    }
  }

  test("live OSV API smoke test (opt-in via -Dosv.liveTests=true)") {
    assume(
      sys.props.get("osv.liveTests").contains("true"),
      "live OSV API tests are disabled; set -Dosv.liveTests=true to enable"
    )

    // A loose smoke test: verify connectivity and parsing, not exact ids/counts (OSV
    // data is mutable), so it never becomes flaky when enabled.
    val result = Client().query(V1Query.of("org.scala-sbt" % "sbt" % "1.11.7"))
    assert(result.isRight, s"live OSV query failed: $result")
  }
}
