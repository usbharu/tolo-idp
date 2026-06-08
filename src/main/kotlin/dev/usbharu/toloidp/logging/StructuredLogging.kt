package dev.usbharu.toloidp.logging

import org.slf4j.Logger
import org.slf4j.spi.LoggingEventBuilder

fun Logger.structuredTrace(message: String, vararg fields: Pair<String, Any?>) {
    atTrace().addFields(fields).log(message)
}

fun Logger.structuredDebug(message: String, vararg fields: Pair<String, Any?>) {
    atDebug().addFields(fields).log(message)
}

fun Logger.structuredInfo(message: String, vararg fields: Pair<String, Any?>) {
    atInfo().addFields(fields).log(message)
}

fun Logger.structuredWarn(message: String, vararg fields: Pair<String, Any?>) {
    atWarn().addFields(fields).log(message)
}

fun Logger.structuredWarn(message: String, throwable: Throwable, vararg fields: Pair<String, Any?>) {
    atWarn().setCause(throwable).addFields(fields).log(message)
}

private fun LoggingEventBuilder.addFields(fields: Array<out Pair<String, Any?>>): LoggingEventBuilder {
    fields.forEach { (key, value) ->
        if (value != null) {
            addKeyValue(key, value)
        }
    }
    return this
}
