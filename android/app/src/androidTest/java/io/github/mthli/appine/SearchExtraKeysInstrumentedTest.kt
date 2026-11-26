package io.github.mthli.appine

import android.content.Intent
import android.view.ContextThemeWrapper
import android.view.KeyEvent
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.allViews
import androidx.core.view.isVisible
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises real [SearchBarView] and [ExtraKeysView] focus and input routing on Android. */
@RunWith(AndroidJUnit4::class)
class SearchExtraKeysInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun findKey(root: View, label: String): TextView =
        root.allViews.filterIsInstance<TextView>().firstOrNull { it.text?.toString() == label }
            ?: throw AssertionError("Extra key '$label' not found")

    private fun findEditText(root: View): EditText =
        root.allViews.filterIsInstance<EditText>().firstOrNull() ?: throw AssertionError("Search EditText not found")

    @Test
    fun extraKeysRouteToFocusedSearchBarAndNeverLeakToTerminal() {
        ActivityScenario.launch<LicensesActivity>(Intent(context, LicensesActivity::class.java)).use { scenario ->
            val searches = mutableListOf<String>()
            val steps = mutableListOf<Boolean>()
            var closed = 0
            val terminalKeys = mutableListOf<Int>()
            val terminalTexts = mutableListOf<String>()

            scenario.onActivity { activity ->
                val themed = ContextThemeWrapper(activity, R.style.Theme_Appine_Terminal)
                lateinit var searchBar: SearchBarView
                lateinit var keys: ExtraKeysView
                val terminal = View(themed).apply {
                    isFocusable = true
                    isFocusableInTouchMode = true
                }
                searchBar = SearchBarView(
                    themed,
                    object : SearchBarView.Target {
                        override fun search(needle: String) { searches.add(needle) }
                        override fun step(older: Boolean) { steps.add(older) }
                        override fun close() {
                            closed++
                            searchBar.isVisible = false
                            terminal.requestFocus()
                        }
                    },
                ).apply { isVisible = false }
                keys = ExtraKeysView(
                    themed,
                    object : ExtraKeysView.Target {
                        override fun key(keyCode: Int) {
                            SearchExtraKeys.routeKey(
                                keyCode = keyCode,
                                locked = false,
                                searchFocused = searchBar.hasInputFocus,
                                onBeforeDispatch = {},
                                onSearchKey = { searchBar.extraKey(it, keys.ctrl, keys.alt, keys.shift) },
                                onTerminalKey = { terminalKeys.add(it) },
                                onSearchModifiersUsed = keys::modifiersUsed,
                            )
                        }

                        override fun text(text: String) {
                            SearchExtraKeys.routeText(
                                text = text,
                                locked = false,
                                searchFocused = searchBar.hasInputFocus,
                                onBeforeDispatch = {},
                                onSearchText = { searchBar.extraText(it, keys.ctrl, keys.alt) },
                                onTerminalText = { terminalTexts.add(it) },
                                onSearchModifiersUsed = keys::modifiersUsed,
                            )
                        }

                        override fun notice(text: String) {}
                    },
                )
                val container = LinearLayout(themed).apply {
                    orientation = LinearLayout.VERTICAL
                    addView(searchBar)
                    addView(terminal, LinearLayout.LayoutParams(100, 100))
                    addView(keys)
                }
                activity.setContentView(container)

                val field = findEditText(searchBar)
                field.setText("old")
                searchBar.open()
                assertTrue("Search bar must hold input focus after open", searchBar.hasInputFocus)
                assertEquals(0, field.selectionStart)
                assertEquals(3, field.selectionEnd)

                // Printable symbol replaces selected previous query and triggers search.
                findKey(keys, "/").performClick()
                assertEquals("/", field.text.toString())
                assertEquals("/", searches.last())

                // Second symbol inserts at caret; Home/Right/Left move cursor inside EditText.
                findKey(keys, "-").performClick()
                assertEquals("/-", field.text.toString())
                findKey(keys, "HOME").performClick()
                assertEquals(0, field.selectionStart)
                findKey(keys, "→").performClick()
                assertEquals(1, field.selectionStart)
                findKey(keys, "|").performClick()
                assertEquals("/|-", field.text.toString())

                // Up/Down step matches; Tab is consumed; none leak to terminal.
                findKey(keys, "↑").performClick()
                findKey(keys, "↓").performClick()
                findKey(keys, "TAB").performClick()
                assertEquals(listOf(true, false), steps)
                assertTrue("Terminal must not receive keys while search has focus", terminalKeys.isEmpty())
                assertTrue("Terminal must not receive text while search has focus", terminalTexts.isEmpty())

                // Ctrl + symbol is suppressed and consumes one-shot Ctrl.
                findKey(keys, "CTRL").performClick()
                assertTrue(keys.ctrl)
                findKey(keys, "~").performClick()
                assertEquals("/|-", field.text.toString())
                assertFalse("One-shot Ctrl must be consumed after search extra key", keys.ctrl)
                assertTrue(terminalTexts.isEmpty())

                // Focusing the terminal while search remains visible routes extra keys back to terminal.
                terminal.requestFocus()
                assertTrue(searchBar.isVisible)
                assertFalse(searchBar.hasInputFocus)
                findKey(keys, "TAB").performClick()
                findKey(keys, "/").performClick()
                assertEquals(listOf(KeyEvent.KEYCODE_TAB), terminalKeys)
                assertEquals(listOf("/"), terminalTexts)

                // Returning focus to search field lets ESC close search without leaking ESC to terminal.
                field.requestFocus()
                assertTrue(searchBar.hasInputFocus)
                findKey(keys, "ESC").performClick()
                assertEquals(1, closed)
                assertFalse(searchBar.isVisible)
                assertEquals(listOf(KeyEvent.KEYCODE_TAB), terminalKeys)
            }
            instrumentation.waitForIdleSync()
        }
    }
}
