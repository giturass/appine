package io.github.mthli.appine

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Verifies shell-integration hooks (bash/ash/zsh marks, continuation rows, right prompts,
 * Debian/nested rc hooks), ash prompt-tap arrow calculation after background output, and
 * two-phase native frame capture with synchronized-output holds and concurrency.
 */
@RunWith(AndroidJUnit4::class)
class VtShellIntegrationTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun fakeEvents(): VtSession.Events = Proxy.newProxyInstance(
        VtSession.Events::class.java.classLoader, arrayOf(VtSession.Events::class.java),
    ) { _, _, _ -> null } as VtSession.Events

    private fun withAlpineStore(name: String, test: (String) -> Unit) {
        val store = File(context.cacheDir, "$name-${System.nanoTime()}")
        store.deleteRecursively()
        try {
            Rootfs.prepare(context, Rootfs.Distro.ALPINE, store = store)
            test(store.path)
        } finally {
            store.deleteRecursively()
        }
    }

    private fun withTerminal(cols: Int = 80, rows: Int = 24, test: (Long, Int, Long) -> Unit) {
        withAlpineStore("vt-shell-test") { store ->
            val machine = Native.start(store, 1, false)
            val console = Native.openConsole(machine, rows, cols)
            val tab = VtNative.create(machine, console, cols, rows, 8, 16)
            try {
                test(machine, console, tab)
            } finally {
                VtNative.destroy(tab)
                Native.closeConsole(machine, console)
                Native.stop(machine)
            }
        }
    }

    private fun captureScreen(tab: Long, cols: Int = 80, rows: Int = 24, full: Boolean = true): Pair<VtFrame, VtScreen> {
        val buf = VtNative.frame(tab, full)
        assertNotNull("Expected non-null frame buffer", buf)
        val frame = VtFrame(buf!!)
        val screen = VtScreen()
        screen.resize(cols, rows)
        frame.takeRows(screen) {}
        return frame to screen
    }

    private fun rowText(screen: VtScreen, y: Int): String {
        val sb = StringBuilder()
        val base = y * screen.cols
        for (x in 0 until screen.cols) {
            val cp = screen.cp[base + x]
            if (cp != 0) sb.appendCodePoint(cp) else sb.append(' ')
        }
        return sb.toString().trimEnd()
    }

    private fun readConsole(machine: Long, console: Int, input: String): String {
        val writer = thread {
            val bytes = input.toByteArray()
            Native.write(machine, console, bytes, 0, bytes.size)
        }
        val out = StringBuilder()
        val buf = ByteArray(4096)
        while (true) {
            val n = Native.read(machine, console, buf)
            if (n <= 0) break
            out.append(String(buf, 0, n, Charsets.UTF_8))
        }
        writer.join(5000)
        return out.toString().replace("\r\n", "\n")
    }

    @Test
    fun zshRightPromptIsNotInputAndMultilineMarksContinuations() = withTerminal { _, _, tab ->
        // Single-line zsh prompt with RPROMPT wrapped in k=r ... B: RPROMPT must not count as input.
        // Cursor ends at col 4 ("$ hi|"), while RPROMPT sits at col 75 ("RIGHT").
        val single = "\u001b]133;A;cl=line\u0007$ \u001b]133;B\u0007" +
            "\u001b[1;76H\u001b]133;P;k=r\u0007RIGHT\u001b]133;B\u0007" +
            "\u001b[1;3Hhi"
        VtNative.print(tab, single.toByteArray())
        assertTrue(VtNative.atPrompt(tab))
        // Tapping on RPROMPT (col 77) must not send right arrows past "hi" (cursor is already at end).
        assertEquals("", String(VtNative.promptClick(tab, 77, 0)!!))
        // Tapping on 'h' (col 2) sends 2 left arrows.
        assertEquals("\u001b[D\u001b[D", String(VtNative.promptClick(tab, 2, 0)!!))
        // Move cursor onto 'h' (col 2), then tap RPROMPT (col 77): moves only past "hi" (2 right arrows).
        VtNative.print(tab, "\u001b[1;3H".toByteArray())
        assertEquals("\u001b[C\u001b[C", String(VtNative.promptClick(tab, 77, 0)!!))

        // Multi-line zsh PS1 with k=c on row 2 and RPROMPT also using k=c (preserving continuation row).
        val multi = "\r\n\u001b]133;C\u0007\u001b]133;D;0\u0007" +
            "\u001b]133;A;cl=line\u0007top\r\n" +
            "\u001b]133;P;k=c\u0007$ \u001b]133;B\u0007" +
            "\u001b[3;76H\u001b]133;P;k=c\u0007RIGHT\u001b]133;B\u0007" +
            "\u001b[3;3Hab"
        VtNative.print(tab, multi.toByteArray())
        assertTrue(VtNative.atPrompt(tab))
        // Tapping on the prompt's first line (row 1) moves to the start of input on row 2 (2 left arrows).
        assertEquals("\u001b[D\u001b[D", String(VtNative.promptClick(tab, 0, 1)!!))
        // Tapping on RPROMPT (col 77, row 2) sends 0 arrows (RPROMPT is not input).
        assertEquals("", String(VtNative.promptClick(tab, 77, 2)!!))
    }

    @Test
    fun ashPromptTapIgnoresRowsAboveResumedInputAfterBackgroundOutput() = withTerminal(cols = 40, rows = 24) { machine, console, tab ->
        val session = VtSession(1, ConsolePty(machine, "", "root"), machine, fakeEvents())
        val pump = thread(name = "test-ash-pump") { VtNative.pump(tab, session) }
        val pid = Native.spawn(
            machine, console, "/bin/ash", arrayOf("ash", "-l"), ConsolePty.ENVIRONMENT,
        )
        fun send(text: String) {
            val bytes = text.toByteArray()
            assertEquals(bytes.size, Native.write(machine, console, bytes, 0, bytes.size))
        }
        fun waitForText(needle: String, timeoutMs: Long = 10_000): VtScreen {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
            while (System.nanoTime() < deadline) {
                val (_, screen) = captureScreen(tab, cols = 40, rows = 24, full = true)
                for (y in 0 until screen.rows) {
                    if (rowText(screen, y).contains(needle)) return screen
                }
                Thread.sleep(25)
            }
            val (_, screen) = captureScreen(tab, cols = 40, rows = 24, full = true)
            val dump = (0 until screen.rows).joinToString("\n") { "$it: ${rowText(screen, it)}" }
            throw AssertionError("Timed out waiting for '$needle'\n$dump")
        }
        try {
            // Wait for login ash prompt, then set a short prompt and clear screen.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
            while (!VtNative.atPrompt(tab) && System.nanoTime() < deadline) Thread.sleep(25)
            assertTrue("Expected ash to reach prompt", VtNative.atPrompt(tab))
            send("clear\n")
            Thread.sleep(200)
            // Start a background job that prints one line while we are at the next prompt.
            send("(sleep 0.3; echo BGLINE) &\n")
            waitForText("BGLINE")
            // Type "def" on the resumed row after BGLINE printed.
            send("def")
            val screen = waitForText("def")
            assertTrue("Cursor must stay at prompt after background output", VtNative.atPrompt(tab))

            val bgRow = (0 until screen.rows).first { rowText(screen, it).contains("BGLINE") }
            val resumedRow = (0 until screen.rows).first { rowText(screen, it).contains("def") }
            assertTrue("Expected resumed row ($resumedRow) below bgRow ($bgRow)", resumedRow > bgRow)

            // Tapping on bgRow (the prompt row above where input resumed) must be ignored (null),
            // NOT count arrows across the background break as if ash had wrapped the command there.
            assertNull("Tap above resumed row must return null", VtNative.promptClick(tab, 0, bgRow))
            // Tapping on 'd' (col 0) of "def" on resumedRow must send 3 left arrows.
            assertEquals("\u001b[D\u001b[D\u001b[D", String(VtNative.promptClick(tab, 0, resumedRow)!!))
            // Tapping on 'f' (col 2) of "def" on resumedRow must send 1 left arrow.
            assertEquals("\u001b[D", String(VtNative.promptClick(tab, 2, resumedRow)!!))

            // Cleanly exit ash.
            send("\u0003exit\n")
            Native.waitFor(machine, pid)
        } finally {
            Native.closeConsole(machine, console)
            pump.join(3000)
        }
    }

    @Test
    fun twoPhaseFrameCaptureHandlesSyncHoldAndConcurrentOutput() = withTerminal { _, _, tab ->
        // Initial frame with styled text and search match.
        VtNative.print(tab, "\u001b[1;32mhello\u001b[0m world\r\nsecond line".toByteArray())
        assertTrue(VtNative.search(tab, "world"))
        val (f1, s1) = captureScreen(tab, full = true)
        assertEquals("hello world", rowText(s1, 0))
        assertEquals("second line", rowText(s1, 1))
        assertEquals(1, f1.searchTotal)
        assertFalse(f1.outputPending)
        // Check bold + green styling survived deferred end_update.
        assertTrue("Expected bold bit on 'h'", s1.attrs[0] and 1 != 0)
        assertTrue("Expected non-default fg on 'h'", s1.fg[0] != 0)
        VtNative.searchEnd(tab)

        // Synchronized output hold: capture pre-hold state while held, then show new state after end.
        VtNative.print(tab, "\u001b[?2026h\r\nHIDDEN_WHILE_HELD".toByteArray())
        val (heldFrame, heldScreen) = captureScreen(tab, full = true)
        assertTrue("Expected outputPending during mode 2026 hold", heldFrame.outputPending)
        assertEquals("", rowText(heldScreen, 2))
        VtNative.print(tab, "\u001b[?2026l".toByteArray())
        val (afterHold, afterScreen) = captureScreen(tab, full = false)
        assertFalse(afterHold.outputPending)
        assertEquals("HIDDEN_WHILE_HELD", rowText(afterScreen, 2))

        // A hold that starts AND ends between two frames must not lose changes made before/during it.
        VtNative.print(tab, "\r\nBEFORE_BURST\u001b[?2026h\r\nINSIDE_BURST\u001b[?2026l".toByteArray())
        val (_, burstScreen) = captureScreen(tab, full = false)
        assertEquals("BEFORE_BURST", rowText(burstScreen, 3))
        assertEquals("INSIDE_BURST", rowText(burstScreen, 4))

        // Stress concurrent output (including mode 2026 holds) against two-phase frame captures.
        val stop = AtomicBoolean(false)
        val failure = AtomicReference<Throwable?>(null)
        val started = CountDownLatch(1)
        val writer = thread(name = "vt-concurrent-writer") {
            started.countDown()
            try {
                for (i in 0 until 400) {
                    val chunk = if (i % 17 == 0) {
                        "\u001b[?2026h\u001b[33mheld-$i\u001b[0m\r\n\u001b[?2026l"
                    } else {
                        "\u001b[1;36mline-$i\u001b[0m payload\r\n"
                    }
                    VtNative.print(tab, chunk.toByteArray())
                }
            } catch (t: Throwable) {
                failure.compareAndSet(null, t)
            } finally {
                stop.set(true)
            }
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        var frames = 0
        while (!stop.get() || frames < 20) {
            val buf = VtNative.frame(tab, frames % 10 == 0)
            assertNotNull(buf)
            val f = VtFrame(buf!!)
            assertEquals(80, f.cols)
            assertEquals(24, f.rows)
            frames++
        }
        writer.join(10_000)
        assertNull(failure.get())
        // Final full frame must show the last line written cleanly.
        val (_, finalScreen) = captureScreen(tab, full = true)
        val allText = (0 until finalScreen.rows).joinToString("\n") { rowText(finalScreen, it) }
        assertTrue("Expected final output in screen:\n$allText", allText.contains("line-399"))
    }

    @Test
    fun shellHooksAndMultilinePs1WorkAcrossDistrosAndUpgrades() = withAlpineStore("shell-hooks") { store ->
        // Fresh Alpine import writes /etc/appine/zsh/.zshenv and does not create /etc/zsh/zshrc yet.
        assertNotNull(Native.readFile(store, "/etc/appine/zsh/.zshenv"))
        assertNull(Native.readFile(store, "/etc/zsh/zshrc"))

        // Simulate Alpine zsh installation (/etc/zsh/zprofile without /etc/zsh/zshrc):
        // updateProfile installs /etc/zsh/zshrc once and respects later user removal.
        Native.writeFile(store, "/etc/zsh/zprofile", "emulate sh -c '. /etc/profile'\n".toByteArray(), 420, true)
        Rootfs.updateProfile(context, store, Rootfs.Distro.ALPINE)
        val alpineZshrc = Native.readFile(store, "/etc/zsh/zshrc")?.decodeToString()
        assertNotNull(alpineZshrc)
        assertTrue(alpineZshrc!!, alpineZshrc.contains("/etc/profile.d/appine.zshrc"))
        assertNotNull(Native.readFile(store, "/var/lib/appine/zsh-rc-hook-done"))

        // Simulate Debian store with /etc/bash.bashrc and /etc/zsh/zshrc:
        withAlpineStore("deb-hooks") { debStore ->
            Native.writeFile(debStore, "/etc/bash.bashrc", "[ -z \"\${PS1-}\" ] && return\nPS1='\\u@\\h:\\w\\$ '\n".toByteArray(), 420, true)
            Native.writeFile(debStore, "/etc/zsh/zshrc", "# stock debian zshrc\n".toByteArray(), 420, true)
            Rootfs.updateProfile(context, debStore, Rootfs.Distro.DEBIAN)
            val debBashrc = Native.readFile(debStore, "/etc/bash.bashrc")!!.decodeToString()
            val debZshrc = Native.readFile(debStore, "/etc/zsh/zshrc")!!.decodeToString()
            assertTrue(debBashrc, debBashrc.contains("/etc/profile.d/appine.bashrc"))
            assertTrue(debZshrc, debZshrc.contains("/etc/profile.d/appine.zshrc"))

            // Removing the appended lines must persist across a subsequent updateProfile.
            Native.writeFile(debStore, "/etc/bash.bashrc", "# user edited\n".toByteArray(), 420, true)
            Native.writeFile(debStore, "/etc/zsh/zshrc", "# user edited\n".toByteArray(), 420, true)
            Rootfs.updateProfile(context, debStore, Rootfs.Distro.DEBIAN)
            assertEquals("# user edited\n", Native.readFile(debStore, "/etc/bash.bashrc")!!.decodeToString())
            assertEquals("# user edited\n", Native.readFile(debStore, "/etc/zsh/zshrc")!!.decodeToString())
        }

        // Verify real Alpine bash and ash emit OSC 133 k=c continuation marks on multi-line PS1.
        val machine = Native.start(store, 1, false)
        fun runShell(program: String, argv: Array<String>, input: String): String {
            val console = Native.openConsole(machine, 24, 80)
            return try {
                val pid = Native.spawn(machine, console, program, argv, ConsolePty.ENVIRONMENT)
                val out = readConsole(machine, console, input)
                Native.waitFor(machine, pid)
                out
            } finally {
                Native.closeConsole(machine, console)
            }
        }
        try {
            val bashOut = runShell(
                "/bin/sh",
                ConsolePty.argv(ConsolePty.script(context), ConsolePty.LOGIN_ROOT),
                "PS1='top\\n\\$ '\ntrue\nexit\n",
            )
            assertTrue(
                "Expected bash multi-line PS1 continuation mark (k=c) in:\n${bashOut.replace("\u001b", "<ESC>").replace("\u0007", "<BEL>")}",
                bashOut.contains("\u001b]133;P;k=c\u0007# \u001b]133;B\u0007"),
            )

            val ashOut = runShell(
                "/bin/ash",
                arrayOf("ash", "-l"),
                "PS1='row1\\n# '; . /etc/profile.d/appine.ashrc\ntrue\nexit\n",
            )
            assertTrue(
                "Expected ash multi-line PS1 continuation mark (k=c;appine_lf=output) in:\n${ashOut.replace("\u001b", "<ESC>").replace("\u0007", "<BEL>")}",
                ashOut.contains("\u001b]133;P;k=c;appine_lf=output\u0007# \u001b]133;B\u0007"),
            )
        } finally {
            Native.stop(machine)
        }
    }

    @Test
    fun doasPreservesAshMarksAndOverwrittenPs1FallsBackToForegroundDetection() = withAlpineStore("doas-fg-fallback") { store ->
        // Unmodified stock 20-wheel.conf upgrades to setenv { ENV=/etc/profile.d/appine.ashrc };
        // customized rules stay untouched.
        Native.writeFile(store, "/etc/doas.d/20-wheel.conf", "permit persist :wheel\n".toByteArray(), 420, true)
        Rootfs.updateProfile(context, store, Rootfs.Distro.ALPINE)
        assertEquals(
            "permit persist setenv { ENV=/etc/profile.d/appine.ashrc } :wheel\n",
            Native.readFile(store, "/etc/doas.d/20-wheel.conf")!!.decodeToString(),
        )
        Native.writeFile(store, "/etc/doas.d/20-wheel.conf", "permit persist :wheel\npermit nopass root\n".toByteArray(), 420, true)
        Rootfs.updateProfile(context, store, Rootfs.Distro.ALPINE)
        assertEquals(
            "permit persist :wheel\npermit nopass root\n",
            Native.readFile(store, "/etc/doas.d/20-wheel.conf")!!.decodeToString(),
        )

        // Stage bundled doas so login.sh installs it for a regular user and switches root to ash.
        context.assets.open("doas.apk").use {
            Native.writeFile(store, "/var/cache/appine/doas.apk", it.readBytes(), 420, true)
        }
        val machine = Native.start(store, 1, false)
        try {
            fun runCmd(cmd: String) {
                val pid = Native.spawn(machine, -1, "/bin/sh", arrayOf("sh", "-c", cmd), ConsolePty.ENVIRONMENT)
                assertEquals(0, Native.waitFor(machine, pid))
            }
            runCmd("rm -f /etc/doas.d/20-wheel.conf && adduser -D -s /bin/sh alice && sed -i '1s|:[^:]*$|:/bin/sh|' /etc/passwd")

            // 1. `doas -s` preserves ENV=/etc/profile.d/appine.ashrc so root ash emits OSC 133 marks.
            val console = Native.openConsole(machine, 24, 80)
            val doasOut = try {
                val pid = Native.spawn(
                    machine, console, "/bin/sh",
                    ConsolePty.argv(ConsolePty.script(context), "alice"),
                    ConsolePty.ENVIRONMENT,
                )
                val out = readConsole(machine, console, "doas -s\necho DOAS_ENV=\$ENV\nexit\nexit\n")
                Native.waitFor(machine, pid)
                out
            } finally {
                Native.closeConsole(machine, console)
            }
            assertEquals(
                "permit persist setenv { ENV=/etc/profile.d/appine.ashrc } :wheel\n",
                Native.readFile(store, "/etc/doas.d/20-wheel.conf")!!.decodeToString(),
            )
            assertTrue("Expected ENV=/etc/profile.d/appine.ashrc inside doas -s:\n$doasOut",
                doasOut.contains("DOAS_ENV=/etc/profile.d/appine.ashrc"))
            assertTrue("Expected OSC 133 prompt mark inside doas -s root ash",
                doasOut.contains("\u001b]133;A;cl=line;appine_lf=output\u0007"))

            // 2. Ash with PS1 overwritten after ENV (no OSC 133 marks) still reports idle/busy,
            // fallback command title and completion timing via foreground-process detection.
            val titles = LinkedBlockingQueue<String>()
            val finished = LinkedBlockingQueue<Pair<Int?, Long>>()
            val events = Proxy.newProxyInstance(
                VtSession.Events::class.java.classLoader, arrayOf(VtSession.Events::class.java),
            ) { _, method, args ->
                when (method.name) {
                    "onTitleChanged" -> titles.offer((args!![0] as VtSession).title.orEmpty())
                    "onCommandFinished" -> finished.offer((args!![1] as Int?) to (args[2] as Long))
                }
                null
            } as VtSession.Events

            val instrumentation = InstrumentationRegistry.getInstrumentation()
            lateinit var session: VtSession
            instrumentation.runOnMainSync {
                session = VtSession(
                    2, ConsolePty(machine, "cd /tmp; exec /bin/ash -l", "root"), machine, events,
                )
                session.start(80, 24, 8, 16)
            }
            fun send(text: String) {
                val bytes = text.toByteArray()
                assertEquals(bytes.size, Native.write(machine, session.console, bytes, 0, bytes.size))
            }
            fun waitUntil(label: String, timeoutMs: Long = 10_000, cond: () -> Boolean) {
                val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
                while (System.nanoTime() < deadline) {
                    if (cond()) return
                    Thread.sleep(25)
                }
                throw AssertionError("Timed out waiting for $label")
            }
            try {
                waitUntil("initial ash prompt") { VtNative.atPrompt(session.tab) }
                assertFalse("Idle marked ash must not be busy", session.busy)

                // Overwrite PS1 so ash stops emitting OSC 133 marks.
                send("PS1='plain> '\n")
                waitUntil("unmarked ash prompt idle") {
                    !VtNative.atPrompt(session.tab) && !session.busy
                }
                titles.clear()
                finished.clear()

                // Run a silent command: fallback must mark busy, report title and fire completion.
                send("sleep 0.3\n")
                waitUntil("fallback busy during sleep") { session.busy }
                waitUntil("fallback title sleep 0.3") { session.title == "sleep 0.3" }
                val done = finished.poll(10, TimeUnit.SECONDS)
                assertNotNull("Expected fallback onCommandFinished", done)
                assertNull("Fallback completion has no exit code", done!!.first)
                assertTrue("Expected non-negative duration, got ${done.second}", done.second >= 100)
                waitUntil("idle after sleep completes") { !session.busy }
            } finally {
                instrumentation.runOnMainSync { session.release() }
            }
        } finally {
            Native.stop(machine)
        }
    }
}
