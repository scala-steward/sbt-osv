/*
 * Copyright 2026 the original author or authors
 *
 * SPDX-License-Identifier: MIT
 */

package net.nmoncho.sbt.osv.api.v1

import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets.UTF_8

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer

/** Minimal in-process HTTP server for deterministic, offline `Client` tests.
  *
  * `handler` receives the request path and body and returns `(status, responseBody)`,
  * letting a test serve canned OSV API responses (including stateful ones for
  * pagination / retry) without touching the network.
  */
final class StubOsvServer(handler: (String, String) => (Int, String)) {

  private val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)

  server.createContext(
    "/",
    (exchange: HttpExchange) => {
      val requestBody    = new String(exchange.getRequestBody.readAllBytes(), UTF_8)
      val (status, body) = handler(exchange.getRequestURI.getPath, requestBody)
      val bytes          = body.getBytes(UTF_8)
      // 0 would mean "chunked"; use -1 to signal no body when the response is empty.
      exchange.sendResponseHeaders(status, if (bytes.isEmpty) -1L else bytes.length.toLong)
      val os = exchange.getResponseBody
      try os.write(bytes)
      finally os.close()
    }
  )

  server.start()

  def baseUrl: String = s"http://127.0.0.1:${server.getAddress.getPort}"

  def stop(): Unit = server.stop(0)
}

object StubOsvServer {

  /** Runs `f` with a started stub server, stopping it afterwards. */
  def withServer[A](handler: (String, String) => (Int, String))(f: StubOsvServer => A): A = {
    val server = new StubOsvServer(handler)
    try f(server)
    finally server.stop()
  }
}
