package io.github.mthli.appine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BackgroundImageTrimTest {
    @Test
    fun quickSwitchCancelsPendingTrim() {
        val trim = BackgroundImageTrim(delayMs = 60_000L, maxRetained = 2)

        assertEquals(emptyList<Int>(), trim.onCurrentChanged(previousId = null, currentId = 1, now = 0L))
        assertNull(trim.nextDelayMs(0L))

        assertEquals(emptyList<Int>(), trim.onCurrentChanged(previousId = 1, currentId = 2, now = 1_000L))
        assertEquals(60_000L, trim.nextDelayMs(1_000L))
        assertEquals(emptyList<Int>(), trim.takeDue(30_000L))

        // Switching back to tab 1 within the grace window protects tab 1 and starts tab 2's window.
        assertEquals(emptyList<Int>(), trim.onCurrentChanged(previousId = 2, currentId = 1, now = 30_000L))
        assertEquals(60_000L, trim.nextDelayMs(30_000L))
        assertEquals(emptyList<Int>(), trim.takeDue(89_999L))
        assertEquals(1L, trim.nextDelayMs(89_999L))

        // Once tab 2 has been unseen for the full grace window, only tab 2 is trimmed.
        assertEquals(0L, trim.nextDelayMs(95_000L))
        assertEquals(listOf(2), trim.takeDue(90_000L))
        assertNull(trim.nextDelayMs(90_000L))
        assertEquals(setOf(2), trim.trimmedIds())
    }

    @Test
    fun lruBudgetEvictsOldestBeyondMaxRetained() {
        val trim = BackgroundImageTrim(delayMs = 60_000L, maxRetained = 2)

        assertEquals(emptyList<Int>(), trim.onCurrentChanged(null, 1, 0L))
        assertEquals(emptyList<Int>(), trim.onCurrentChanged(1, 2, 1_000L))
        assertEquals(emptyList<Int>(), trim.onCurrentChanged(2, 3, 2_000L))
        // 3 background tabs (1, 2, 3) exceed maxRetained = 2 -> oldest (1) trims immediately.
        assertEquals(listOf(1), trim.onCurrentChanged(3, 4, 3_000L))
        assertEquals(setOf(1), trim.trimmedIds())
        // Earliest still pending is tab 2 (left at 2_000L).
        assertEquals(59_000L, trim.nextDelayMs(3_000L))

        // Leaving tab 4 for tab 5 evicts tab 2 immediately.
        assertEquals(listOf(2), trim.onCurrentChanged(4, 5, 4_000L))
        assertEquals(setOf(1, 2), trim.trimmedIds())

        // Remaining recent background tabs trim in order as their grace windows expire.
        assertEquals(listOf(3), trim.takeDue(63_000L))
        assertEquals(1_000L, trim.nextDelayMs(63_000L))
        assertEquals(listOf(4), trim.takeDue(64_000L))
        assertNull(trim.nextDelayMs(64_000L))
        assertEquals(setOf(1, 2, 3, 4), trim.trimmedIds())
    }

    @Test
    fun revisitingTabProtectsItAndRefreshesLruOrder() {
        val trim = BackgroundImageTrim(delayMs = 60_000L, maxRetained = 2)

        trim.onCurrentChanged(null, 1, 0L)
        trim.onCurrentChanged(1, 2, 1_000L)
        trim.onCurrentChanged(2, 3, 2_000L)
        assertEquals(listOf(1), trim.onCurrentChanged(3, 4, 3_000L))
        assertEquals(setOf(1), trim.trimmedIds())

        // Returning to trimmed tab 1 removes it from trimmedIds and leaves tab 4 pending,
        // evicting the oldest pending tab (2).
        assertEquals(listOf(2), trim.onCurrentChanged(4, 1, 4_000L))
        assertEquals(setOf(2), trim.trimmedIds())

        // Visiting pending tab 3 refreshes the order: pending is now [4, 1] (no eviction).
        assertEquals(emptyList<Int>(), trim.onCurrentChanged(1, 3, 5_000L))
        assertEquals(setOf(2), trim.trimmedIds())
        assertEquals(59_000L, trim.nextDelayMs(5_000L))
        // Jumping past both grace windows trims both pending tabs at once.
        assertEquals(listOf(4, 1), trim.takeDue(120_000L))
        assertNull(trim.nextDelayMs(120_000L))
        assertEquals(setOf(2, 4, 1), trim.trimmedIds())
    }

    @Test
    fun markAllTrimmedProtectsCurrentAndClearsPendingTimers() {
        val trim = BackgroundImageTrim(delayMs = 60_000L, maxRetained = 2)

        trim.onCurrentChanged(null, 1, 0L)
        trim.onCurrentChanged(1, 2, 1_000L)
        trim.onCurrentChanged(2, 3, 2_000L)

        // UI-hidden or system-pressure trim cuts tabs 1 and 2, keeping current tab 3 untouched.
        trim.markAllTrimmed(currentId = 3, openIds = listOf(1, 2, 3))
        assertNull(trim.nextDelayMs(2_000L))
        assertEquals(emptyList<Int>(), trim.takeDue(120_000L))
        assertEquals(setOf(1, 2), trim.trimmedIds())

        // With no current tab, every open started tab is recorded as trimmed.
        trim.markAllTrimmed(currentId = null, openIds = listOf(1, 2, 3))
        assertEquals(setOf(1, 2, 3), trim.trimmedIds())
    }

    @Test
    fun removeSameTabAndClearHandleEdgeCases() {
        val trim = BackgroundImageTrim(delayMs = 60_000L, maxRetained = 2)

        // Setting the same tab again is a no-op.
        assertEquals(emptyList<Int>(), trim.onCurrentChanged(1, 1, 0L))
        assertNull(trim.nextDelayMs(0L))

        trim.onCurrentChanged(1, 2, 1_000L)
        trim.onCurrentChanged(2, 3, 2_000L)
        trim.onCurrentChanged(3, 4, 3_000L) // evicts 1 to trimmed; pending = [2, 3]

        trim.remove(1)
        trim.remove(2)
        assertEquals(emptySet<Int>(), trim.trimmedIds())
        assertEquals(60_000L, trim.nextDelayMs(3_000L)) // tab 3 left at 3_000L

        trim.remove(3)
        assertNull(trim.nextDelayMs(3_000L))

        trim.onCurrentChanged(4, 5, 4_000L)
        trim.clear()
        assertNull(trim.nextDelayMs(4_000L))
        assertEquals(emptySet<Int>(), trim.trimmedIds())
    }
}
