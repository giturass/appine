package io.github.mthli.appine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipboardReadsTest {
    private class Tab {
        var now = 0L
        var due: Long? = null
        var timer: Runnable? = null
        var previews = 0
        var dismissals = 0
        val replies = mutableListOf<String>()
        val tokens = mutableListOf<ClipboardReads.Token>()
        val reads = ClipboardReads(
            schedule = { task, delay ->
                check(timer == null)
                due = now + delay
                timer = task
            },
            cancelTimeout = { task ->
                if (task === timer) {
                    timer = null
                    due = null
                }
            },
            reply = { bytes, token ->
                replies.add(bytes.decodeToString())
                tokens.add(token)
            },
        )

        fun deliver(resumed: Boolean = true, focused: Boolean = true, locked: Boolean = false): Boolean {
            val claimed = reads.beginPrompt(resumed, focused, locked) { dismissals++ }
            if (claimed) previews++
            return claimed
        }

        fun advanceTo(time: Long) {
            now = time
            if (now >= (due ?: return)) {
                val task = checkNotNull(timer)
                timer = null
                due = null
                task.run()
            }
        }
    }

    @Test
    fun backgroundReadWaitsThenCoalescesTargetsBeforeAndDuringOnePrompt() {
        val tab = Tab()
        assertTrue(tab.reads.enqueue('c', 1))
        tab.advanceTo(35_000)
        assertFalse(tab.reads.enqueue('p', 1))
        assertEquals(60_000L, tab.due)
        assertTrue(tab.replies.isEmpty())
        assertTrue(tab.deliver())
        assertFalse(tab.reads.enqueue('s', 1))
        assertFalse(tab.deliver())
        assertNull(tab.timer)
        tab.advanceTo(120_000)
        assertTrue(tab.replies.isEmpty())
        tab.reads.answer("雪")
        assertEquals(listOf(reply('c', "6Zuq") + reply('p', "6Zuq") + reply('s', "6Zuq")), tab.replies)
        assertEquals(1, tab.previews)
        assertFalse(tab.deliver())
    }

    @Test
    fun lockedPausedAndUnfocusedEachDeferUntilReady() {
        val tab = Tab()
        tab.reads.enqueue('p', 1)
        assertFalse(tab.deliver(locked = true))
        assertFalse(tab.deliver(resumed = false))
        assertFalse(tab.deliver(focused = false))
        assertEquals(0, tab.previews)
        assertTrue(tab.replies.isEmpty())
        assertTrue(tab.deliver())
        tab.reads.denyPrompt() // Privacy-mode pause with an open preview.
        assertEquals(1, tab.dismissals)
        assertEquals(listOf(reply('p')), tab.replies)
        tab.reads.answer("stale preview")
        assertEquals(1, tab.replies.size)
    }

    @Test
    fun waitingReadsExpireAtTheFirstDeadlineAndAnotherBatchCanStart() {
        val tab = Tab()
        tab.reads.enqueue('p', 2)
        tab.advanceTo(59_999)
        tab.reads.enqueue('c', 1)
        tab.reads.denyPrompt() // Switching away without an open preview leaves this batch waiting.
        assertTrue(tab.replies.isEmpty())
        tab.advanceTo(60_000)
        assertEquals(listOf(reply('p').repeat(2) + reply('c')), tab.replies)
        assertFalse(tab.deliver())
        assertTrue(tab.reads.enqueue('s', 1))
        assertEquals(120_000L, tab.due)
        assertTrue(tab.deliver())
        tab.reads.answer("") // Empty or non-text clipboard.
        assertEquals(reply('s'), tab.replies.last())
    }

    @Test
    fun overflowGetsEmptyRepliesWhileOnly64ReadsCanReceiveTheClipboard() {
        val tab = Tab()
        tab.reads.enqueue('c', 63)
        tab.reads.enqueue('p', 3)
        assertEquals(listOf(reply('p').repeat(2)), tab.replies)
        assertTrue(tab.deliver())
        tab.reads.enqueue('s', 12)
        assertEquals(reply('s').repeat(12), tab.replies.last())
        tab.reads.answer("x")
        assertEquals(reply('c', "eA==").repeat(63) + reply('p', "eA=="), tab.replies.last())
        assertEquals(3, tab.replies.size)
    }

    @Test
    fun switchDeniesOnlyTheOpenPreviewAndTheNewTabCanPrompt() {
        val first = Tab()
        val second = Tab()
        first.reads.enqueue('c', 1)
        assertTrue(first.deliver())
        second.reads.enqueue('s', 1)
        first.reads.denyPrompt()
        assertEquals(listOf(reply('c')), first.replies)
        assertEquals(1, first.dismissals)
        assertTrue(second.deliver())
        first.reads.answer("old")
        second.reads.answer("new")
        assertEquals(listOf(reply('s', "bmV3")), second.replies)
        assertEquals(1, first.replies.size)
    }

    @Test
    fun sessionCleanupDropsWaitingReadsAndInvalidatesPostedWork() {
        val tab = Tab()
        val generation = tab.reads.generation
        tab.reads.enqueue('c', 5)
        tab.reads.clear()
        assertFalse(tab.reads.generation == generation)
        assertNull(tab.timer)
        tab.advanceTo(90_000)
        assertFalse(tab.deliver())
        assertTrue(tab.replies.isEmpty())
        assertEquals(0, tab.dismissals)
    }

    @Test
    fun resetDismissesAPreviewWithoutReplyingAndTheNextReadStartsFresh() {
        val tab = Tab()
        tab.reads.enqueue('p', 2)
        assertTrue(tab.deliver())
        tab.reads.clear()
        assertEquals(1, tab.dismissals)
        assertTrue(tab.reads.enqueue('s', 1))
        tab.reads.answer("stale")
        assertTrue(tab.replies.isEmpty())
        assertTrue(tab.deliver())
        tab.reads.answer("x")
        assertEquals(listOf(reply('s', "eA==")), tab.replies)
    }

    @Test
    fun userResetDropsLateReadCapturedBeforeReset() {
        val tab = Tab()
        tab.reads.enqueue('c', 1)
        assertTrue(tab.deliver())
        tab.reads.clear()
        assertEquals(1, tab.dismissals)
        tab.reads.resetTo(1)
        assertEquals(1, tab.dismissals)
        assertFalse(tab.reads.enqueue('p', 1, readGeneration = 0))
        assertFalse(tab.deliver())
        assertNull(tab.timer)
        assertTrue(tab.replies.isEmpty())
    }

    @Test
    fun userResetAcceptsReadCapturedAfterReset() {
        val tab = Tab()
        tab.reads.clear()
        tab.reads.resetTo(1)
        assertTrue(tab.reads.enqueue('c', 1, readGeneration = 1))
        assertTrue(tab.deliver())
        tab.reads.answer("x")
        assertEquals(listOf(reply('c', "eA==")), tab.replies)
        assertTrue(tab.reads.isCurrent(tab.tokens.single()))
    }

    @Test
    fun programResetInvalidatesQueuedReplyBeforeDismissingPreview() {
        val tab = Tab()
        tab.reads.enqueue('c', 65) // An overflow reply is already queued on the writer.
        val overflow = tab.tokens.single()
        assertTrue(tab.reads.isCurrent(overflow))
        assertTrue(tab.deliver())

        tab.reads.observeNativeGeneration(1)
        assertFalse(tab.reads.isCurrent(overflow))
        assertTrue(tab.reads.isStale(0))
        assertFalse(tab.reads.enqueue('p', 1, readGeneration = 0))
        assertTrue(tab.reads.promptActive)
        tab.reads.resetTo(1)
        assertEquals(1, tab.dismissals)
        tab.reads.answer("old")
        assertEquals(listOf(reply('c')), tab.replies)
        assertFalse(tab.reads.enqueue('p', 1, readGeneration = 0))
        assertTrue(tab.reads.enqueue('s', 1, readGeneration = 1))
        assertTrue(tab.deliver())
        tab.reads.answer("x")
        assertEquals(listOf(reply('c'), reply('s', "eA==")), tab.replies)
    }

    @Test
    fun delayedResetKeepsReadsFromANewerGeneration() {
        val tab = Tab()
        tab.reads.clear()
        tab.reads.resetTo(2)
        tab.reads.enqueue('p', 1, readGeneration = 2)
        val timer = tab.timer
        tab.reads.resetTo(2)
        tab.reads.resetTo(1)
        assertEquals(2L, tab.reads.currentNativeGeneration)
        assertEquals(timer, tab.timer)
        assertTrue(tab.deliver())
        tab.reads.answer("x")
        assertEquals(listOf(reply('p', "eA==")), tab.replies)
        assertTrue(tab.reads.isCurrent(tab.tokens.single()))
    }

    @Test
    fun newerReadReplacesOldBatchAndUsesTheNewNativeGeneration() {
        val tab = Tab()
        tab.reads.enqueue('p', 1)
        assertTrue(tab.deliver())
        assertTrue(tab.reads.enqueue('s', 1, readGeneration = 2))
        assertEquals(2L, tab.reads.currentNativeGeneration)
        assertEquals(1, tab.dismissals)
        assertTrue(tab.replies.isEmpty())
        assertTrue(tab.deliver())
        tab.reads.answer("x")
        assertEquals(listOf(reply('s', "eA==")), tab.replies)
        assertEquals(ClipboardReads.Token(tab.reads.generation, 2), tab.tokens.single())
        assertTrue(tab.reads.isCurrent(tab.tokens.single()))
    }

    @Test
    fun writerChecksBothLocalAndNativeGenerations() {
        val tab = Tab()
        fun answeredRead(): ClipboardReads.Token {
            assertTrue(tab.reads.enqueue('c', 1))
            assertTrue(tab.deliver())
            tab.reads.answer("x")
            return tab.tokens.last().also { assertTrue(tab.reads.isCurrent(it)) }
        }

        val beforeClear = answeredRead()
        tab.reads.clear()
        assertFalse(tab.reads.isCurrent(beforeClear))
        val beforeObservation = answeredRead()
        tab.reads.observeNativeGeneration(1)
        assertFalse(tab.reads.isCurrent(beforeObservation))
        tab.reads.resetTo(1)
        val beforeReset = answeredRead()
        tab.reads.resetTo(2)
        assertFalse(tab.reads.isCurrent(beforeReset))
        answeredRead()
    }

    private fun reply(target: Char, data: String = "") = "\u001b]52;$target;$data\u001b\\"
}
