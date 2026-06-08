package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader

class CachedBodyHttpServletRequest(
    request: HttpServletRequest,
) : HttpServletRequestWrapper(request) {
    private val body = request.inputStream.readAllBytes()

    fun cachedBody(): ByteArray = body

    override fun getInputStream(): ServletInputStream =
        CachedBodyServletInputStream(body)

    override fun getReader(): BufferedReader =
        BufferedReader(InputStreamReader(inputStream, characterEncoding ?: Charsets.UTF_8.name()))
}

private class CachedBodyServletInputStream(
    body: ByteArray,
) : ServletInputStream() {
    private val delegate = ByteArrayInputStream(body)

    override fun read(): Int = delegate.read()

    override fun isFinished(): Boolean = delegate.available() == 0

    override fun isReady(): Boolean = true

    override fun setReadListener(readListener: ReadListener?) {
        // Synchronous servlet processing only.
    }
}

