package io.github.mthli.appine

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import android.os.SystemClock
import android.view.ContextThemeWrapper
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inspector.WindowInspector
import android.widget.TextView
import androidx.core.graphics.createBitmap
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Exercises the real input connection and paste encoder without sending input to a shell. */
@RunWith(AndroidJUnit4::class)
class TerminalInputTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun onMain(action: () -> Unit) {
        instrumentation.runOnMainSync(action)
        instrumentation.waitForIdleSync()
    }

    private class Host : VtView.Host {
        val bytes = ByteArrayOutputStream()
        val focusEvents = mutableListOf<Pair<Int, String>>()
        override fun onInput(data: ByteArray) { bytes.write(data) }
        override fun onFocus(session: VtSession, data: ByteArray) {
            focusEvents.add(session.id to String(data, Charsets.UTF_8))
            onInput(data)
        }
        override fun onGrid(cols: Int, rows: Int, cellWidth: Int, cellHeight: Int) {}
        override fun onZoom(fontPx: Int) {}
        override val ctrl = false
        override val alt = false
        override val shift = false
        override fun modifiersUsed() {}
        override fun onLink(uri: String) {}
        override fun onSearchCount(total: Int, selected: Int) {}
        fun text() = bytes.toString("UTF-8")
    }

    private data class Fixture(
        val view: VtView,
        val connection: InputConnection,
        val host: Host,
        val tab: Long,
        val session: VtSession,
        val statusChanges: AtomicInteger,
        val machine: Long,
        val console: Int,
    )

    private fun fakeEvents(onStatusChanged: () -> Unit = {}): VtSession.Events = Proxy.newProxyInstance(
        VtSession.Events::class.java.classLoader, arrayOf(VtSession.Events::class.java),
    ) { _, method, _ ->
        if (method.name == "onStatusChanged") onStatusChanged()
        null
    } as VtSession.Events

    private fun field(clazz: Class<*>, name: String) =
        clazz.getDeclaredField(name).apply { isAccessible = true }

    private fun withConnection(test: (InputConnection, Host, Long) -> Unit) =
        withFixture { test(it.connection, it.host, it.tab) }

    private fun <A : Activity> ActivityScenario<A>.await(
        description: String, timeoutMillis: Long = 60_000, condition: (A) -> Boolean,
    ) {
        val deadline = SystemClock.uptimeMillis() + timeoutMillis
        do {
            var ready = false
            onActivity { ready = condition(it) }
            if (ready) return
            SystemClock.sleep(25)
        } while (SystemClock.uptimeMillis() < deadline)
        throw AssertionError("Timed out waiting for $description")
    }

    private fun withFixture(test: (Fixture) -> Unit) {
        val root = File(context.cacheDir, "terminal-input-test").apply { mkdirs() }
        val tar = File(root, "rootfs.tgz")
        context.assets.open("rootfs.tgz").use { input -> tar.outputStream().use(input::copyTo) }
        Native.importRootfs(File(root, "store").path, tar.path)
        val machine = Native.start(File(root, "store").path, 1, false)
        val console = Native.openConsole(machine, 24, 80)
        val tab = VtNative.create(machine, console, 80, 24, 8, 16)
        try {
            ActivityScenario.launch<LicensesActivity>(Intent(context, LicensesActivity::class.java)).use { scenario ->
                lateinit var view: VtView
                lateinit var connection: InputConnection
                lateinit var session: VtSession
                val host = Host()
                val statusChanges = AtomicInteger()
                scenario.onActivity { activity ->
                    assertFalse("Tests require an unlocked page", Privacy.locked(activity))
                    session = VtSession(1, ConsolePty(machine, "", "root"), machine, fakeEvents { statusChanges.incrementAndGet() })
                    // Supply only the terminal; starting a session would also start shell threads.
                    field(VtSession::class.java, "tab").setLong(session, tab)
                    view = VtView(ContextThemeWrapper(activity, R.style.Theme_Appine_Terminal), host)
                    view.attach(session)
                    connection = view.onCreateInputConnection(EditorInfo())
                }
                try {
                    // Clipboard reads require window focus, which can follow ActivityScenario's resume.
                    scenario.await("the test page to gain window focus", 5000) { it.hasWindowFocus() }
                    test(Fixture(view, connection, host, tab, session, statusChanges, machine, console))
                } finally {
                    onMain {
                        button(android.R.id.button2)?.performClick()
                        view.attach(null)
                    }
                }
            }
        } finally {
            VtNative.destroy(tab)
            Native.closeConsole(machine, console)
            Native.stop(machine)
            root.deleteRecursively()
        }
    }

    private fun button(id: Int): View? = WindowInspector.getGlobalWindowViews()
        .firstNotNullOfOrNull { it.findViewById(id) }

    private fun hasPreview(): Boolean {
        fun contains(view: View): Boolean =
            (view is TextView && view.text == context.getString(R.string.paste_unsafe_title)) ||
                (view is ViewGroup && (0 until view.childCount).any { contains(view.getChildAt(it)) })
        return WindowInspector.getGlobalWindowViews().any(::contains)
    }

    @Test
    fun removingTrailingNewlinesPreservesOtherWhitespaceAndDoesNotReplay() {
        withConnection { connection, host, _ ->
            onMain {
                connection.commitText("  printf hello \t\r\n\r\n", 1)
                assertTrue(hasPreview())
                assertEquals("", host.text())
                assertTrue("A safe alternative must be offered", button(android.R.id.button3)?.visibility == View.VISIBLE)
            }
            if (InstrumentationRegistry.getArguments().getString("screenshots") == "true") {
                SystemClock.sleep(500) // Let the dialog's window animation finish before visual inspection.
                val screenshot = instrumentation.uiAutomation.takeScreenshot()!!
                File(context.cacheDir, "paste-preview.png").outputStream().use {
                    screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)
                }
                screenshot.recycle()
            }
            onMain { button(android.R.id.button3)!!.performClick() }
            onMain {
                connection.finishComposingText()
                assertEquals("  printf hello \t", host.text())
                assertFalse(hasPreview())
            }
        }
    }

    @Test
    fun removingTrailingNewlinesIsNotOfferedForUnsafeOrEmptyRemainders() {
        withConnection { connection, host, _ ->
            for (text in listOf("first\nsecond\n", "first\u001b[201~\n", "\r\n\r\n")) {
                onMain {
                    connection.commitText(text, 1)
                    assertTrue(hasPreview())
                    assertFalse("Unsafe or empty text must not be offered", button(android.R.id.button3)?.visibility == View.VISIBLE)
                    assertEquals("", host.text())
                    button(android.R.id.button2)!!.performClick()
                }
            }
        }
    }

    @Test
    fun removingTrailingNewlinesUsesCurrentPasteMode() {
        withConnection { connection, host, tab ->
            onMain {
                connection.commitText("hello\n", 1)
                assertTrue(hasPreview())
                assertTrue(button(android.R.id.button3)?.visibility == View.VISIBLE)
                VtNative.print(tab, "\u001b[?2004h".toByteArray())
                button(android.R.id.button3)!!.performClick()
            }
            assertEquals("\u001b[200~hello\u001b[201~", host.text())
        }
    }

    @Test
    fun switchingSessionsInvalidatesBothPasteActions() {
        withFixture { f ->
            val other = VtSession(2, ConsolePty(f.machine, "", "root"), f.machine, fakeEvents())
            field(VtSession::class.java, "tab").setLong(other, f.tab)
            for (action in listOf(android.R.id.button1, android.R.id.button3)) {
                onMain {
                    f.view.attach(f.session)
                    f.connection.commitText("echo hello\n", 1)
                    assertTrue(hasPreview())
                    val staleButton = button(action)!!
                    f.view.attach(other)
                    // A click already enqueued when a notification switched tabs must also be harmless.
                    staleButton.performClick()
                }
                assertEquals("", f.host.text())
                onMain { assertFalse(hasPreview()) }
            }
        }
    }

    @Test
    fun clipboardReadCanAskAgainAfterSwitchAndStop() {
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use { scenario ->
            val serviceField = field(MainActivity::class.java, "service")
            fun service(activity: MainActivity) =
                serviceField.get(activity) as? TerminalService
            fun select(session: VtSession) {
                scenario.onActivity {
                    it.startActivity(Intent(it, MainActivity::class.java).putExtra(MainActivity.EXTRA_TAB, session.id))
                }
                scenario.await("tab ${session.id} to gain focus") { it.hasWindowFocus() && service(it)?.current === session }
            }
            fun ask(session: VtSession) {
                session.onClipboardRead('c'.code, 1)
                scenario.await("the clipboard question for tab ${session.id}") {
                    val allow = button(android.R.id.button1) as? TextView
                    allow?.text?.toString().equals(context.getString(R.string.allow), ignoreCase = true)
                }
            }
            scenario.await("the first terminal session") { it.hasWindowFocus() && service(it)?.current != null }
            lateinit var owner: TerminalService
            lateinit var original: VtSession
            lateinit var first: VtSession
            lateinit var second: VtSession
            val clipboard = context.getSystemService(ClipboardManager::class.java)
            val previous = clipboard.primaryClip
            scenario.onActivity {
                owner = service(it)!!
                original = owner.current!!
                first = owner.createSession()
                second = owner.createSession()
                clipboard.setPrimaryClip(ClipData.newPlainText("Test", "clipboard read test"))
            }
            try {
                select(first)
                ask(first)
                select(second)
                ask(second)
                scenario.moveToState(Lifecycle.State.CREATED)
                scenario.moveToState(Lifecycle.State.RESUMED)
                scenario.await("the second tab to resume") { it.hasWindowFocus() && service(it)?.current === second }
                ask(second)
                select(first)
                ask(first)
            } finally {
                select(original)
                scenario.onActivity {
                    owner.removeSession(first)
                    owner.removeSession(second)
                    if (previous == null) clipboard.clearPrimaryClip() else clipboard.setPrimaryClip(previous)
                }
            }
        }
    }

    @Test
    fun replacementIsDeliveredImmediatelyAndNotReplayedOnFinish() {
        assumeTrue(Build.VERSION.SDK_INT >= 34)
        withConnection { connection, host, _ ->
            onMain {
                assertTrue(connection.replaceText(0, 0, "first", 1, null))
                assertEquals("first", host.text())
                assertEquals("", connection.getTextBeforeCursor(100, 0).toString())
                connection.finishComposingText()
                assertEquals("first", host.text())
                connection.replaceText(0, 0, "second", 1, null)
                connection.finishComposingText()
                assertEquals("firstsecond", host.text())
            }
        }
    }

    @Test
    fun replacementRequiresConfirmationBeforeSendingLineBreaks() {
        assumeTrue(Build.VERSION.SDK_INT >= 34)
        withConnection { connection, host, _ ->
            onMain {
                connection.replaceText(0, 0, "first\nsecond", 1, null)
                assertTrue("Replacement must show the paste preview", hasPreview())
                assertEquals("", host.text())
                connection.finishComposingText()
                assertEquals("", host.text())
                button(android.R.id.button1)!!.performClick()
            }
            assertEquals("first\rsecond", host.text())
        }
    }

    @Test
    fun finishingCompositionUsesPasteSafetyAndCancellationDiscardsIt() {
        withConnection { connection, host, _ ->
            onMain {
                connection.setComposingText("first\nsecond", 1)
                connection.finishComposingText()
                assertTrue("Finishing composition must show the paste preview", hasPreview())
                assertEquals("", host.text())
                button(android.R.id.button2)!!.performClick()
            }
            onMain {
                connection.finishComposingText()
                connection.commitText("ok", 1)
                assertEquals("ok", host.text())
            }
        }
    }

    @Test
    fun imePasteMenuUsesClipboardSafety() {
        withConnection { connection, host, _ ->
            val clipboard = context.getSystemService(ClipboardManager::class.java)
            val previous = clipboard.primaryClip
            try {
                onMain {
                    clipboard.setPrimaryClip(ClipData.newPlainText("Test", "first\nsecond"))
                    assertTrue(connection.performContextMenuAction(android.R.id.paste))
                    assertTrue("IME paste must show the paste preview", hasPreview())
                    assertEquals("", host.text())
                    button(android.R.id.button2)!!.performClick()
                }
                onMain {
                    connection.finishComposingText()
                    assertEquals("", host.text())
                }
            } finally {
                if (previous == null) clipboard.clearPrimaryClip() else clipboard.setPrimaryClip(previous)
            }
        }
    }

    @Test
    fun ordinaryCompositionAndEnterStillTypeOnce() {
        withConnection { connection, host, _ ->
            onMain {
                connection.setComposingText("ni", 1)
                assertEquals("", host.text())
                connection.commitText("你", 1)
                connection.finishComposingText()
                connection.setComposingText("好", 1)
                connection.finishComposingText()
                connection.finishComposingText()
                connection.commitText("\n", 1)
                assertEquals("你好\r", host.text())
                assertFalse(hasPreview())
            }
        }
    }

    @Test
    fun bracketedPasteAndItsTerminatorUseTheSameChecksForComposition() {
        withConnection { connection, host, tab ->
            onMain {
                VtNative.print(tab, "\u001b[?2004h".toByteArray())
                connection.setComposingText("first\nsecond", 1)
                connection.finishComposingText()
                assertEquals("\u001b[200~first\nsecond\u001b[201~", host.text())
                assertFalse(hasPreview())
                host.bytes.reset()
                connection.setComposingText("\u001b[201~", 1)
                connection.finishComposingText()
                assertTrue("The bracketed paste terminator must require confirmation", hasPreview())
                assertEquals("", host.text())
            }
        }
    }

    @Test
    fun deletingSurroundingTextPreservesComposition() {
        withFixture { f ->
            val preeditField = field(VtView::class.java, "preedit")
            onMain {
                f.connection.setComposingText("abc", 1)
                assertEquals("abc", preeditField.get(f.view))
                f.connection.deleteSurroundingText(1, 0)
                assertEquals("abc", preeditField.get(f.view))
                f.connection.deleteSurroundingTextInCodePoints(1, 0)
                assertEquals("abc", preeditField.get(f.view))
                assertEquals("", f.host.text())
                f.connection.finishComposingText()
                assertEquals("", preeditField.get(f.view))
                assertEquals("abc", f.host.text())
            }
        }
    }

    @Test
    fun attachClearsPreeditAndStopsBlink() {
        withFixture { f ->
            val preeditField = field(VtView::class.java, "preedit")
            val blinkField = field(VtView::class.java, "blinkRunning")
            onMain {
                f.connection.setComposingText("hello", 1)
                blinkField.setBoolean(f.view, true)
                assertEquals("hello", preeditField.get(f.view))
                f.view.attach(null)
                assertEquals("", preeditField.get(f.view))
                assertFalse("Detaching must stop cursor blink", blinkField.getBoolean(f.view))
            }
        }
    }

    @Test
    fun mode1004FocusEventsDoNotJumpScrolledBackViewport() {
        withFixture { f ->
            val atBottomField = field(VtView::class.java, "atBottom")
            onMain {
                f.view.layout(0, 0, 640, 384)
                VtNative.print(f.tab, ("\u001b[?1004h" + (1..60).joinToString("\r\n") { "line $it" }).toByteArray())
                val bitmap = createBitmap(f.view.width, f.view.height)
                try {
                    f.view.draw(Canvas(bitmap))
                    VtNative.scroll(f.tab, -5)
                    f.view.draw(Canvas(bitmap))
                    assertFalse("Viewport must be scrolled back before focus events", atBottomField.getBoolean(f.view))

                    f.view.onWindowFocusChanged(false)
                    f.view.onWindowFocusChanged(true)
                    assertEquals("\u001b[O\u001b[I", f.host.text())

                    f.view.draw(Canvas(bitmap))
                    assertFalse("Focus events must not jump viewport to bottom", atBottomField.getBoolean(f.view))
                } finally {
                    bitmap.recycle()
                }
            }
        }
    }

    @Test
    fun switchingTabsSendsMode1004FocusOutAndFocusInWithoutDuplicates() {
        withFixture { f ->
            val console2 = Native.openConsole(f.machine, 24, 80)
            val tab2 = VtNative.create(f.machine, console2, 80, 24, 8, 16)
            val console3 = Native.openConsole(f.machine, 24, 80)
            val tab3 = VtNative.create(f.machine, console3, 80, 24, 8, 16)
            try {
                val session2 = VtSession(2, ConsolePty(f.machine, "", "root"), f.machine, fakeEvents())
                field(VtSession::class.java, "tab").setLong(session2, tab2)
                val session3 = VtSession(3, ConsolePty(f.machine, "", "root"), f.machine, fakeEvents())
                field(VtSession::class.java, "tab").setLong(session3, tab3)
                onMain {
                    VtNative.print(f.tab, "\u001b[?1004h".toByteArray())
                    VtNative.print(tab2, "\u001b[?1004h".toByteArray())
                    // Initial attach before window focus must not emit spurious focus events.
                    assertEquals(emptyList<Pair<Int, String>>(), f.host.focusEvents)

                    // Window gains focus once; repeated focus-in and re-attaching the same session are ignored.
                    f.view.onWindowFocusChanged(true)
                    f.view.onWindowFocusChanged(true)
                    f.view.attach(f.session)
                    assertEquals(listOf(1 to "\u001b[I"), f.host.focusEvents)

                    // Switching tabs while focused delivers focus-out to old session and focus-in to new session.
                    f.host.focusEvents.clear()
                    f.view.attach(session2)
                    assertEquals(listOf(1 to "\u001b[O", 2 to "\u001b[I"), f.host.focusEvents)

                    // Switching to a tab without mode 1004 sends focus-out to old tab and nothing to new tab.
                    f.host.focusEvents.clear()
                    f.view.attach(session3)
                    assertEquals(listOf(2 to "\u001b[O"), f.host.focusEvents)

                    // Switching back to a mode-1004 tab sends only focus-in to the incoming tab.
                    f.host.focusEvents.clear()
                    f.view.attach(f.session)
                    assertEquals(listOf(1 to "\u001b[I"), f.host.focusEvents)

                    // Backgrounding sends focus-out once; switching tabs while backgrounded emits nothing.
                    f.host.focusEvents.clear()
                    f.view.onWindowFocusChanged(false)
                    f.view.onWindowFocusChanged(false)
                    f.view.attach(session2)
                    assertEquals(listOf(1 to "\u001b[O"), f.host.focusEvents)

                    // Returning to foreground sends focus-in to the newly attached tab.
                    f.host.focusEvents.clear()
                    f.view.onWindowFocusChanged(true)
                    assertEquals(listOf(2 to "\u001b[I"), f.host.focusEvents)

                    // Losing focus then detaching (e.g. Activity.onDestroy) must not send duplicate focus-out.
                    f.host.focusEvents.clear()
                    f.view.onWindowFocusChanged(false)
                    f.view.attach(null)
                    assertEquals(listOf(2 to "\u001b[O"), f.host.focusEvents)

                    // Reattaching after window focus was already gained delivers a single focus-in.
                    f.host.focusEvents.clear()
                    f.view.onWindowFocusChanged(true)
                    assertEquals(emptyList<Pair<Int, String>>(), f.host.focusEvents)
                    f.view.attach(f.session)
                    assertEquals(listOf(1 to "\u001b[I"), f.host.focusEvents)
                }
            } finally {
                onMain { f.view.attach(null) }
                VtNative.destroy(tab2)
                Native.closeConsole(f.machine, console2)
                VtNative.destroy(tab3)
                Native.closeConsole(f.machine, console3)
            }
        }
    }

    @Test
    fun sessionResetClearsProgressAndStatus() {
        withFixture { f ->
            onMain {
                f.session.onProgress(VtSession.PROGRESS_SET, 40)
                f.session.onStatus(VtSession.STATUS_WORKING, VtSession.KIND_NONE, 40, "job", "Build", "Running")
            }
            onMain {
                assertEquals(VtSession.Progress(VtSession.PROGRESS_SET, 40), f.session.progress)
                assertEquals("job", f.session.status?.id)
                val before = f.statusChanges.get()
                f.session.reset()
                assertNull(f.session.progress)
                assertNull(f.session.status)
                assertTrue("Reset must notify status change when clearing progress/status", f.statusChanges.get() > before)
            }
        }
    }

    private fun Fixture.pumpReports(vararg sequences: String) {
        // Queue a single write before starting the pump so it sees the whole batch.
        val stream = sequences.joinToString("") { "\u001b]$it\u0007" }
        val pid = Native.spawn(
            machine, console, "/bin/sh", arrayOf("sh", "-c", "printf '%s' \"\$1\"", "sh", stream),
            ConsolePty.ENVIRONMENT,
        )
        assertEquals(0, Native.waitFor(machine, pid))
        VtNative.pump(tab, session)
        instrumentation.waitForIdleSync()
    }

    @Test
    fun promptExpiresOnlyEarlierTransientReports() {
        withFixture { f ->
            f.pumpReports(
                "7501;state=done:id=finished", "7501;state=blocked:id=old", "9;4;1;45",
                "133;A", "7501;state=working:id=next", "133;P;k=s",
            )
            onMain {
                assertNull(f.session.progress)
                assertEquals("finished", f.session.status?.id)
                f.session.statusSeen()
                assertEquals("next", f.session.status?.id)
            }
        }
    }

    @Test
    fun commandEndKeepsErrorsAndLaterProgress() {
        withFixture { f ->
            f.pumpReports("7501;state=error:id=failed", "7501;state=blocked:id=old")
            onMain { assertEquals("old", f.session.status?.id) }
            f.pumpReports("133;D;1", "9;4;1;70")
            onMain {
                assertEquals(VtSession.Progress(VtSession.PROGRESS_SET, 70), f.session.progress)
                assertEquals("failed", f.session.status?.id)
                f.session.statusSeen()
                assertNull(f.session.status)
            }
        }
    }

    @Test
    fun foregroundChangeKeepsLaterReportsInTheQueue() {
        val session = VtSession(1, ConsolePty(0L, "", "root"), 0L, fakeEvents())
        onMain {
            // Keep the main thread from draining the first report before the next two callbacks.
            session.onStatus(VtSession.STATUS_BLOCKED, 0, -1, "old", "", "")
            session.onForeground()
            session.onStatus(VtSession.STATUS_WORKING, 0, -1, "next", "", "")
        }
        onMain { assertEquals("next", session.status?.id) }
    }

    @Test
    fun sessionHangUpDropsQueuedWrites() {
        val blockerStarted = CountDownLatch(1)
        val releaseBlocker = CountDownLatch(1)
        val executor = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue())
        val pty = ConsolePty(0L, "", "root")
        field(ConsolePty::class.java, "console").setInt(pty, 0)
        val session = VtSession(1, pty, 0L, fakeEvents())
        field(VtSession::class.java, "writer").set(session, executor)
        try {
            executor.execute {
                blockerStarted.countDown()
                try {
                    releaseBlocker.await(5, TimeUnit.SECONDS)
                } catch (_: InterruptedException) {
                    // shutdownNow interrupts the running task while dropping queued writes.
                }
            }
            assertTrue(blockerStarted.await(5, TimeUnit.SECONDS))
            session.write("queued".toByteArray())
            assertEquals(1, executor.queue.size)
            session.finishIfRunning()
            assertEquals("Queued writes must be cancelled on hangup", 0, executor.queue.size)
            assertTrue(executor.isShutdown)
            releaseBlocker.countDown()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals(1L, executor.completedTaskCount)
        } finally {
            releaseBlocker.countDown()
            executor.shutdownNow()
        }
    }
}
