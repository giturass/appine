package io.github.mthli.appine

import android.view.KeyEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SearchExtraKeysTest {
    @Test
    fun routeKeyToSearchNeverLeaksToTerminalAndConsumesModifiers() {
        val searchKeys = mutableListOf<Int>()
        val terminalKeys = mutableListOf<Int>()
        var beforeCount = 0
        var modifiersUsedCount = 0

        SearchExtraKeys.routeKey(
            keyCode = KeyEvent.KEYCODE_ESCAPE,
            locked = false,
            searchFocused = true,
            onBeforeDispatch = { beforeCount++ },
            onSearchKey = { searchKeys.add(it) },
            onTerminalKey = { terminalKeys.add(it) },
            onSearchModifiersUsed = { modifiersUsedCount++ },
        )

        assertEquals(1, beforeCount)
        assertEquals(listOf(KeyEvent.KEYCODE_ESCAPE), searchKeys)
        assertEquals(emptyList<Int>(), terminalKeys)
        assertEquals(1, modifiersUsedCount)
    }

    @Test
    fun routeTextToSearchNeverLeaksToTerminalAndConsumesModifiers() {
        val searchTexts = mutableListOf<String>()
        val terminalTexts = mutableListOf<String>()
        var modifiersUsedCount = 0

        SearchExtraKeys.routeText(
            text = "/",
            locked = false,
            searchFocused = true,
            onBeforeDispatch = {},
            onSearchText = { searchTexts.add(it) },
            onTerminalText = { terminalTexts.add(it) },
            onSearchModifiersUsed = { modifiersUsedCount++ },
        )

        assertEquals(listOf("/"), searchTexts)
        assertEquals(emptyList<String>(), terminalTexts)
        assertEquals(1, modifiersUsedCount)
    }

    @Test
    fun routeWhenSearchUnfocusedSendsToTerminalWithoutConsumingSearchModifiers() {
        val searchKeys = mutableListOf<Int>()
        val terminalKeys = mutableListOf<Int>()
        val searchTexts = mutableListOf<String>()
        val terminalTexts = mutableListOf<String>()
        var modifiersUsedCount = 0

        SearchExtraKeys.routeKey(
            keyCode = KeyEvent.KEYCODE_DPAD_UP,
            locked = false,
            searchFocused = false,
            onBeforeDispatch = {},
            onSearchKey = { searchKeys.add(it) },
            onTerminalKey = { terminalKeys.add(it) },
            onSearchModifiersUsed = { modifiersUsedCount++ },
        )
        SearchExtraKeys.routeText(
            text = "|",
            locked = false,
            searchFocused = false,
            onBeforeDispatch = {},
            onSearchText = { searchTexts.add(it) },
            onTerminalText = { terminalTexts.add(it) },
            onSearchModifiersUsed = { modifiersUsedCount++ },
        )

        assertEquals(emptyList<Int>(), searchKeys)
        assertEquals(listOf(KeyEvent.KEYCODE_DPAD_UP), terminalKeys)
        assertEquals(emptyList<String>(), searchTexts)
        assertEquals(listOf("|"), terminalTexts)
        assertEquals(0, modifiersUsedCount)
    }

    @Test
    fun routeWhenPrivacyLockedIgnoresBothSearchAndTerminal() {
        var beforeDispatched = false
        var searchHit = false
        var terminalHit = false
        var modifiersConsumed = false

        SearchExtraKeys.routeKey(
            keyCode = KeyEvent.KEYCODE_ESCAPE,
            locked = true,
            searchFocused = true,
            onBeforeDispatch = { beforeDispatched = true },
            onSearchKey = { searchHit = true },
            onTerminalKey = { terminalHit = true },
            onSearchModifiersUsed = { modifiersConsumed = true },
        )
        SearchExtraKeys.routeText(
            text = "/",
            locked = true,
            searchFocused = false,
            onBeforeDispatch = { beforeDispatched = true },
            onSearchText = { searchHit = true },
            onTerminalText = { terminalHit = true },
            onSearchModifiersUsed = { modifiersConsumed = true },
        )

        assertFalse(beforeDispatched)
        assertFalse(searchHit)
        assertFalse(terminalHit)
        assertFalse(modifiersConsumed)
    }

    @Test
    fun escapeClosesSearchEvenWithModifiers() {
        val state = SearchEditState("foo", 0, 3)
        assertEquals(
            SearchExtraKeyResult.Close,
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_ESCAPE, ctrl = false, alt = false, shift = false, state),
        )
        assertEquals(
            SearchExtraKeyResult.Close,
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_ESCAPE, ctrl = true, alt = false, shift = false, state),
        )
        assertEquals(
            SearchExtraKeyResult.Close,
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_ESCAPE, ctrl = false, alt = true, shift = true, state),
        )
    }

    @Test
    fun upAndDownStepThroughMatches() {
        val state = SearchEditState("error", 5, 5)
        assertEquals(
            SearchExtraKeyResult.Step(older = true),
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_DPAD_UP, ctrl = false, alt = false, shift = false, state),
        )
        assertEquals(
            SearchExtraKeyResult.Step(older = false),
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_DPAD_DOWN, ctrl = false, alt = false, shift = false, state),
        )
        assertEquals(
            SearchExtraKeyResult.Consume,
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_DPAD_UP, ctrl = true, alt = false, shift = false, state),
        )
        assertEquals(
            SearchExtraKeyResult.Consume,
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_DPAD_DOWN, ctrl = false, alt = true, shift = false, state),
        )
    }

    @Test
    fun navigationMovesCursorCollapsesSelectionAndSupportsShiftSelection() {
        var state = SearchEditState("abcd", 2, 2)

        state = applyKey(state, KeyEvent.KEYCODE_DPAD_LEFT)
        assertEquals(SearchEditState("abcd", 1, 1), state)

        state = applyKey(state, KeyEvent.KEYCODE_MOVE_HOME)
        assertEquals(SearchEditState("abcd", 0, 0), state)

        state = applyKey(state, KeyEvent.KEYCODE_DPAD_LEFT)
        assertEquals(SearchEditState("abcd", 0, 0), state)

        state = applyKey(state, KeyEvent.KEYCODE_MOVE_END)
        assertEquals(SearchEditState("abcd", 4, 4), state)

        state = applyKey(state, KeyEvent.KEYCODE_DPAD_RIGHT)
        assertEquals(SearchEditState("abcd", 4, 4), state)

        // Shift+Left extends selection backward; another Shift+Left extends further.
        state = applyKey(state, KeyEvent.KEYCODE_DPAD_LEFT, shift = true)
        assertEquals(SearchEditState("abcd", 4, 3), state)
        state = applyKey(state, KeyEvent.KEYCODE_DPAD_LEFT, shift = true)
        assertEquals(SearchEditState("abcd", 4, 2), state)

        // Unmodified Left collapses backward selection to its left edge.
        val collapsedLeft = applyKey(state, KeyEvent.KEYCODE_DPAD_LEFT)
        assertEquals(SearchEditState("abcd", 2, 2), collapsedLeft)

        // Unmodified Right collapses backward selection to its right edge.
        val collapsedRight = applyKey(state, KeyEvent.KEYCODE_DPAD_RIGHT)
        assertEquals(SearchEditState("abcd", 4, 4), collapsedRight)

        // Shift+Home selects to the beginning from anchor.
        state = applyKey(SearchEditState("abcd", 3, 3), KeyEvent.KEYCODE_MOVE_HOME, shift = true)
        assertEquals(SearchEditState("abcd", 3, 0), state)

        // Shift+End selects to the end from anchor.
        state = applyKey(SearchEditState("abcd", 1, 1), KeyEvent.KEYCODE_MOVE_END, shift = true)
        assertEquals(SearchEditState("abcd", 1, 4), state)
    }

    @Test
    fun textInsertsAtCaretReplacesSelectionAndBlocksCtrlAlt() {
        // Replaces select-all (as set by SearchBarView.open).
        var state = applyText(SearchEditState("previous", 0, 8), "/")
        assertEquals(SearchEditState("/", 1, 1), state)

        // Inserts at caret in the middle.
        state = applyText(SearchEditState("usrbin", 3, 3), "/")
        assertEquals(SearchEditState("usr/bin", 4, 4), state)

        // Handles reversed (backward) selection safely.
        state = applyText(SearchEditState("hello", 4, 1), "-")
        assertEquals(SearchEditState("h-o", 2, 2), state)

        // Unset selection (-1, -1) appends at end.
        state = applyText(SearchEditState("abc", -1, -1), "$")
        assertEquals(SearchEditState("abc$", 4, 4), state)

        // Ctrl or Alt held prevents raw insertion.
        assertEquals(
            SearchExtraKeyResult.Consume,
            SearchExtraKeys.handleText("/", ctrl = true, alt = false, state),
        )
        assertEquals(
            SearchExtraKeyResult.Consume,
            SearchExtraKeys.handleText("~", ctrl = false, alt = true, state),
        )

        // Line breaks are stripped from single-line search input.
        assertEquals(
            SearchExtraKeyResult.Consume,
            SearchExtraKeys.handleText("\r\n", ctrl = false, alt = false, state),
        )
    }

    @Test
    fun delRemovesSelectionOrPrecedingCharacter() {
        assertEquals(
            SearchEditState("ho", 1, 1),
            applyKey(SearchEditState("hello", 4, 1), KeyEvent.KEYCODE_DEL),
        )
        assertEquals(
            SearchEditState("ab", 2, 2),
            applyKey(SearchEditState("abc", 3, 3), KeyEvent.KEYCODE_DEL),
        )
        assertEquals(
            SearchExtraKeyResult.Consume,
            SearchExtraKeys.handleKey(KeyEvent.KEYCODE_DEL, ctrl = false, alt = false, shift = false, SearchEditState("abc", 0, 0)),
        )
    }

    @Test
    fun terminalOnlyKeysAreConsumedWithoutMutatingSearch() {
        val state = SearchEditState("abc", 1, 1)
        val terminalOnly = listOf(
            KeyEvent.KEYCODE_TAB,
            KeyEvent.KEYCODE_PAGE_UP,
            KeyEvent.KEYCODE_PAGE_DOWN,
            KeyEvent.KEYCODE_F1,
            KeyEvent.KEYCODE_F5,
            KeyEvent.KEYCODE_F12,
        )
        for (code in terminalOnly) {
            assertEquals(
                SearchExtraKeyResult.Consume,
                SearchExtraKeys.handleKey(code, ctrl = false, alt = false, shift = false, state),
            )
        }
    }

    private fun applyKey(state: SearchEditState, keyCode: Int, shift: Boolean = false): SearchEditState {
        val result = SearchExtraKeys.handleKey(keyCode, ctrl = false, alt = false, shift = shift, state)
        assertTrue("Expected Edit result for key $keyCode, got $result", result is SearchExtraKeyResult.Edit)
        return SearchExtraKeys.applyEdit(state, result as SearchExtraKeyResult.Edit)
    }

    private fun applyText(state: SearchEditState, text: String): SearchEditState {
        val result = SearchExtraKeys.handleText(text, ctrl = false, alt = false, state)
        assertTrue("Expected Edit result for text $text, got $result", result is SearchExtraKeyResult.Edit)
        return SearchExtraKeys.applyEdit(state, result as SearchExtraKeyResult.Edit)
    }
}
