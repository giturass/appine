package io.github.mthli.appine

import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/** One tab's OSC 52 reads, owned by the main thread. */
internal class ClipboardReads(
    private val schedule: (Runnable, Long) -> Unit,
    private val cancelTimeout: (Runnable) -> Unit,
    private val reply: (ByteArray, Token) -> Unit,
) {
    data class Token(val generation: Long, val nativeGeneration: Long)

    private val targets = StringBuilder()
    private val timeout = Runnable { if (!promptActive) drain(null) }
    private var dismissPrompt: (() -> Unit)? = null
    val promptActive: Boolean get() = dismissPrompt != null

    // The pump can observe a RIS before the main thread applies it to the queue.
    private val latestNativeGeneration = AtomicLong(0L)
    private var appliedNativeGeneration = 0L
    val currentNativeGeneration: Long get() = latestNativeGeneration.get()

    @Volatile
    var generation = 0L
        private set

    fun observeNativeGeneration(nativeGeneration: Long) {
        latestNativeGeneration.accumulateAndGet(nativeGeneration, ::maxOf)
    }

    fun isStale(readGeneration: Long): Boolean = readGeneration < currentNativeGeneration

    fun isCurrent(token: Token): Boolean =
        token.generation == generation && token.nativeGeneration == currentNativeGeneration

    fun resetTo(nativeGeneration: Long) {
        if (nativeGeneration <= appliedNativeGeneration) return
        observeNativeGeneration(nativeGeneration)
        appliedNativeGeneration = nativeGeneration
        clear()
    }

    /** Only the first waiting read starts a deadline and needs an immediate attempt at delivery. */
    fun enqueue(target: Char, count: Int, readGeneration: Long = appliedNativeGeneration): Boolean {
        if (count <= 0 || isStale(readGeneration)) return false
        resetTo(readGeneration)
        val first = targets.isEmpty()
        val accepted = minOf(count, MAX_CLIPBOARD_READS - targets.length)
        repeat(accepted) { targets.append(target) }
        // Deny overflow immediately, including while a question is open. Each pump read is 64 KiB.
        if (accepted < count) {
            reply(sequence(target, "").repeat(count - accepted).toByteArray(), Token(generation, appliedNativeGeneration))
        }
        if (first) schedule(timeout, CLIPBOARD_READ_TIMEOUT_MS)
        return first
    }

    /** Claim the batch before the UI reads the clipboard. An open question has no deadline. */
    fun beginPrompt(resumed: Boolean, focused: Boolean, locked: Boolean, dismiss: () -> Unit): Boolean {
        if (targets.isEmpty() || promptActive || !resumed || !focused || locked) return false
        cancelTimeout(timeout)
        dismissPrompt = dismiss
        return true
    }

    fun answer(text: String?) {
        if (promptActive) drain(text)
    }

    /** A switch, stop or privacy-mode pause denies only a question already on screen. */
    fun denyPrompt() {
        val dismiss = dismissPrompt ?: return
        answer(null)
        dismiss()
    }

    private fun drain(text: String?) {
        if (targets.isEmpty()) return
        val data = Base64.getEncoder().encodeToString(text.orEmpty().toByteArray())
        val bytes = buildString { for (target in targets) append(sequence(target, data)) }.toByteArray()
        targets.clear()
        dismissPrompt = null
        reply(bytes, Token(generation, appliedNativeGeneration))
    }

    /** Drop all requests on release, shell exit or reset, including the displayed preview. */
    fun clear() {
        generation++
        cancelTimeout(timeout)
        targets.clear()
        val dismiss = dismissPrompt
        dismissPrompt = null
        dismiss?.invoke()
    }

    private fun sequence(target: Char, data: String) = "\u001b]52;$target;$data\u001b\\"

    companion object {
        private const val MAX_CLIPBOARD_READS = 64
        private const val CLIPBOARD_READ_TIMEOUT_MS = 60_000L
    }
}
