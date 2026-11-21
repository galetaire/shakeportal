package io.github.galetaire.fingertip

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * The proxy the VPN hands to every app, on the phone's loopback. It looks at
 * each site name:
 *  - ICANN names (and IP addresses) go straight out, resolved by Android as
 *    usual: the proxy only passes the bytes through.
 *  - Handshake names go to the DANE proxy ([DaneProxy], Go) on [danePort],
 *    which resolves them, checks their TLSA record and re-signs them with the
 *    local CA.
 * It logs every site, so the log shows what went where.
 */
class LocalProxy(
    private val port: Int,
    private val danePort: Int,
    private val isHandshake: (String) -> Boolean,
) {
    @Volatile private var server: ServerSocket? = null

    val running: Boolean get() = server?.isClosed == false

    fun start() {
        if (running) return
        // Loopback only: other devices on the network can never use it.
        // Explicitly IPv4 127.0.0.1, the address the VPN hands to apps:
        // Android's InetAddress.getLoopbackAddress() is IPv6 ::1, and a socket
        // bound there refuses connections to 127.0.0.1.
        val socket = ServerSocket(port, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        server = socket
        EventLog.add("Proxy listening on ${socket.inetAddress.hostAddress}:${socket.localPort}")
        thread(name = "proxy-accept", isDaemon = true) {
            while (!socket.isClosed) {
                val client = try {
                    socket.accept()
                } catch (e: Exception) {
                    break
                }
                thread(name = "proxy-conn", isDaemon = true) { handle(client) }
            }
            EventLog.add("Proxy stopped")
        }
    }

    fun stop() {
        server?.close()
        server = null
    }

    private fun handle(client: Socket) {
        client.use {
            try {
                client.soTimeout = 30_000
                val input = client.getInputStream()
                val head = readHead(input) ?: return
                val requestLine = head.substringBefore("\r\n")
                val parts = requestLine.split(" ")
                if (parts.size < 3) return

                if (parts[0].equals("CONNECT", ignoreCase = true)) {
                    // HTTPS: "CONNECT host:443 HTTP/1.1"
                    val (host, port) = splitHostPort(parts[1], 443)
                    if (isHandshake(host)) {
                        EventLog.add("HNS    $host:$port → DANE proxy")
                        toDaneProxy(client, head)
                        return
                    }
                    EventLog.add("HTTPS  $host:$port")
                    val remote = Socket()
                    remote.connect(InetSocketAddress(host, port), 10_000)
                    remote.use {
                        client.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                        client.soTimeout = 0
                        pipe(client, remote)
                    }
                } else {
                    // Plain HTTP: "GET http://host/path HTTP/1.1"
                    val url = parts[1]
                    if (!url.startsWith("http://")) return
                    val hostPort = url.removePrefix("http://").substringBefore("/")
                    val path = "/" + url.removePrefix("http://").substringAfter("/", "")
                    val (host, port) = splitHostPort(hostPort, 80)
                    if (isHandshake(host)) {
                        EventLog.add("HNS    http://$host$path".take(120) + " → DANE proxy")
                        toDaneProxy(client, head)
                        return
                    }
                    EventLog.add("HTTP   $host$path".take(120))
                    val remote = Socket()
                    remote.connect(InetSocketAddress(host, port), 10_000)
                    remote.use {
                        val rest = head.substringAfter("\r\n")
                        remote.getOutputStream().write("${parts[0]} $path ${parts[2]}\r\n$rest".toByteArray())
                        client.soTimeout = 0
                        pipe(client, remote)
                    }
                }
            } catch (e: Exception) {
                EventLog.add("Error: ${e.message}".take(160))
            }
        }
    }

    /**
     * Hands the whole request, as received, to the DANE proxy and connects
     * the two. It answers the browser itself (also the "200" of a CONNECT).
     */
    private fun toDaneProxy(client: Socket, head: String) {
        val remote = Socket()
        try {
            remote.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), danePort), 5_000)
        } catch (e: Exception) {
            EventLog.add("Error: DANE proxy not reachable (${e.message})".take(160))
            client.getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".toByteArray())
            remote.close()
            return
        }
        remote.use {
            remote.getOutputStream().write(head.toByteArray(Charsets.ISO_8859_1))
            client.soTimeout = 0
            pipe(client, remote)
        }
    }

    /** The request line and headers, up to the empty line, as text */
    private fun readHead(input: InputStream): String? {
        val buffer = ByteArrayOutputStream()
        var last4 = 0
        while (buffer.size() < 16 * 1024) {
            val b = input.read()
            if (b < 0) return null
            buffer.write(b)
            last4 = (last4 shl 8) or b
            if (last4 == 0x0D0A0D0A) return buffer.toString(Charsets.ISO_8859_1.name())
        }
        return null
    }

    private fun splitHostPort(value: String, defaultPort: Int): Pair<String, Int> {
        if (value.startsWith("[")) {
            val host = value.substringAfter("[").substringBefore("]")
            val port = value.substringAfter("]:", "").toIntOrNull() ?: defaultPort
            return host to port
        }
        val colon = value.lastIndexOf(':')
        return if (colon > 0) value.substring(0, colon) to (value.substring(colon + 1).toIntOrNull() ?: defaultPort)
        else value to defaultPort
    }

    /** Copy both ways until either side closes */
    private fun pipe(a: Socket, b: Socket) {
        val done = Object()
        fun copy(from: InputStream, to: OutputStream) = thread(isDaemon = true) {
            try {
                from.copyTo(to)
            } catch (_: Exception) {
            }
            synchronized(done) { done.notifyAll() }
        }
        synchronized(done) {
            copy(a.getInputStream(), b.getOutputStream())
            copy(b.getInputStream(), a.getOutputStream())
            done.wait()
        }
    }
}
