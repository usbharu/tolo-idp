package dev.usbharu.toloidp.logging

import ch.qos.logback.classic.spi.ILoggingEvent
import com.google.cloud.spring.logging.JsonLoggingEventEnhancer

class KeyValueLoggingEventEnhancer : JsonLoggingEventEnhancer {
    override fun enhanceJsonLogEntry(jsonMap: MutableMap<String, Any>, event: ILoggingEvent) {
        event.keyValuePairs.orEmpty().forEach { keyValuePair ->
            val key = keyValuePair.key
            val value = keyValuePair.value
            if (key != null && value != null) {
                jsonMap.putIfAbsent(key, value)
            }
        }
    }
}
