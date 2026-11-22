package io.github.mthli.appine

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import android.view.View
import android.view.inspector.WindowInspector
import android.widget.Button
import android.widget.TextView
import androidx.core.content.edit
import androidx.preference.SwitchPreferenceCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** The distribution fixture contains packaged Vulkan tools, a gpu user and the survey binaries. */
@RunWith(AndroidJUnit4::class)
class GpuTest {
    private fun run(machine: Long, script: String, user: String = "gpu"): String {
        val console = Native.openConsole(machine, 24, 120)
        try {
            val pid = Native.spawn(machine, console, "/bin/su", arrayOf("su", "-s", "/bin/sh", user, "-c", script),
                arrayOf("PATH=/usr/local/bin:/usr/bin:/bin:/sbin", "HOME=/tmp"))
            val output = StringBuilder()
            val buf = ByteArray(4096)
            while (true) {
                val n = Native.read(machine, console, buf)
                if (n <= 0) break
                val s = buf.decodeToString(0, n)
                output.append(s)
                Log.i("appine-gpu-test", s)
            }
            assertEquals(output.toString(), 0, Native.waitFor(machine, pid))
            return output.toString()
        } finally {
            Native.closeConsole(machine, console)
        }
    }

    private fun assertOutputContains(output: String, vararg expected: String) {
        for (text in expected) assertTrue("Missing '$text' in guest output:\n$output", text in output)
    }

    private fun reclaimed() {
        val deadline = SystemClock.uptimeMillis() + 5000
        do {
            val memory = File("/proc/self/maps").useLines { lines -> lines.count { "vkr-shmem" in it } }
            val workers = File("/proc/self/task").listFiles().orEmpty().count {
                runCatching { File(it, "comm").readText().trim() }.getOrNull() in setOf("venus-retire", "venus-allocate")
            }
            if (memory == 0 && workers == 0) return
            SystemClock.sleep(25)
        } while (SystemClock.uptimeMillis() < deadline)
        throw AssertionError("Renderer mappings or workers survived machine shutdown")
    }

    private fun assertNoRenderNode(gpu: Boolean) {
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File.createTempFile("venus-", ".store", app.cacheDir)
        check(dir.delete() && dir.mkdir())
        val tar = File.createTempFile("venus-", ".tgz", app.cacheDir)
        var machine = 0L
        try {
            app.assets.open("rootfs.tgz").use { input -> tar.outputStream().use(input::copyTo) }
            Native.importRootfs(dir.path, tar.path)
            machine = Native.start(dir.path, 1, gpu)
            assertFalse(Native.hasGpu(machine))
            run(machine, CHECK_NO_GPU, "nobody")
        } finally {
            if (machine != 0L) Native.stop(machine)
            dir.deleteRecursively()
            tar.delete()
        }
    }

    @Test(timeout = 60000)
    fun disabledByDefault() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val hadGpu = prefs.contains("gpu")
        val previous = prefs.getBoolean("gpu", false)
        try {
            prefs.edit(commit = true) { remove("gpu") }
            assertFalse(Settings.gpu(app))
            assertNoRenderNode(gpu = false)
        } finally {
            prefs.edit(commit = true) {
                if (hadGpu) putBoolean("gpu", previous) else remove("gpu")
            }
        }
    }

    @Test(timeout = 60000)
    fun unsupportedDriver() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("gpuUnsupported") == "true")
        assertNoRenderNode(gpu = true)
    }

    @Test(timeout = 300000)
    fun distributionVenus() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val cache = app.cacheDir
        val distro = InstrumentationRegistry.getArguments().getString("gpuDistro")
        assumeTrue(distro == "alpine" || distro == "debian")
        val tar = File(cache, "venus-$distro.tgz")
        assertTrue("Missing distribution fixture $tar", tar.isFile)
        val dir = File.createTempFile("venus-", ".store", cache)
        check(dir.delete() && dir.mkdir())
        var machine = 0L
        try {
            Native.importRootfs(dir.path, tar.path)
            Rootfs.ensureGpuCommand(app, dir.path)
            machine = Native.start(dir.path, 1, true)
            assertTrue(Native.hasGpu(machine))
            val discovery = run(machine, "set -e; id; /tmp/lifetime; vulkaninfo --summary; /tmp/compute")
            assertOutputContains(discovery, "uid=1000", "DRIVER_ID_MESA_VENUS", "llvmpipe", "verified=65536")
            val hardware = run(machine, "appine-gpu /tmp/compute")
            assertOutputContains(hardware, "driver=venus", "verified=65536")
            assertFalse(hardware, "llvmpipe" in hardware)

            val concurrent = run(machine, """
                appine-gpu /tmp/compute --kill-in-flight & victim=$!
                appine-gpu /tmp/compute & survivor=$!
                echo terminal-responsive
                wait ${'$'}victim
                test $? -eq 137 || exit 1
                wait ${'$'}survivor
            """.trimIndent())
            assertOutputContains(concurrent, "terminal-responsive", "unsignaled submission fence", "verified=65536")
            Native.stop(machine)
            machine = 0
            reclaimed()
            machine = Native.start(dir.path, 1, true)
            assertTrue(Native.hasGpu(machine))
            assertOutputContains(run(machine, "/tmp/compute"), "verified=65536")
        } finally {
            if (machine != 0L) Native.stop(machine)
            dir.deleteRecursively()
        }
        reclaimed()
    }

    @Test(timeout = 180000)
    fun toggleRestartsKernel() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val app = instrumentation.targetContext
        val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val hadGpu = prefs.contains("gpu")
        val previousGpu = prefs.getBoolean("gpu", false)
        val previousPrivacy = Settings.privacyMode(app)
        prefs.edit(commit = true) {
            putBoolean("privacy_mode", false)
            putBoolean("gpu", false)
        }

        val bound = CountDownLatch(1)
        var service: TerminalService? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                service = (binder as TerminalService.LocalBinder).service
                bound.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) {
                service = null
            }
        }

        fun awaitCondition(description: String, timeoutMs: Long = 30000, predicate: () -> Boolean) {
            val deadline = SystemClock.uptimeMillis() + timeoutMs
            while (SystemClock.uptimeMillis() < deadline) {
                if (predicate()) return
                SystemClock.sleep(50)
            }
            throw AssertionError("Timed out waiting for: $description")
        }

        fun awaitMachine(previous: Long = 0L): Long {
            var handle = 0L
            awaitCondition("kernel handle != $previous") {
                instrumentation.runOnMainSync { handle = service?.machine ?: 0L }
                handle != 0L && handle != previous
            }
            return handle
        }

        fun findDialogRoot(expectedMessage: String): View? =
            WindowInspector.getGlobalWindowViews().lastOrNull { root ->
                root.findViewById<TextView>(android.R.id.message)?.text?.toString() == expectedMessage
            }

        fun clickDialogButton(expectedMessage: String, buttonId: Int, expectedLabel: String? = null) {
            var dialog: View? = null
            awaitCondition("confirmation dialog ($expectedMessage)") {
                instrumentation.runOnMainSync { dialog = findDialogRoot(expectedMessage) }
                dialog != null
            }
            instrumentation.runOnMainSync {
                val button = dialog!!.findViewById<Button>(buttonId)
                assertNotNull(button)
                if (expectedLabel != null) assertEquals(expectedLabel, button.text.toString())
                button.performClick()
            }
        }

        fun toggleInSettings(
            expectChecked: Boolean,
            expectSummary: String,
            targetValue: Boolean,
            expectedDialogMessage: String,
        ) {
            ActivityScenario.launch<SettingsActivity>(Intent(app, SettingsActivity::class.java)).use { scenario ->
                fun gpuPref(activity: SettingsActivity): SwitchPreferenceCompat {
                    val fragment = activity.supportFragmentManager.findFragmentById(R.id.content) as SettingsFragment
                    return fragment.findPreference("settings_gpu")!!
                }
                awaitCondition("settings_gpu preference bound and enabled") {
                    var ready = false
                    scenario.onActivity { activity ->
                        val pref = gpuPref(activity)
                        ready = pref.isEnabled && pref.isChecked == expectChecked && pref.summary == expectSummary
                    }
                    ready
                }
                // Cancel must leave both the preference and the running kernel untouched.
                val beforeCancel = awaitMachine()
                scenario.onActivity { activity ->
                    val pref = gpuPref(activity)
                    assertFalse(pref.onPreferenceChangeListener!!.onPreferenceChange(pref, targetValue))
                }
                clickDialogButton(expectedDialogMessage, android.R.id.button2)
                awaitCondition("dialog dismissed after cancel") {
                    var open = true
                    instrumentation.runOnMainSync { open = findDialogRoot(expectedDialogMessage) != null }
                    !open
                }
                scenario.onActivity { activity ->
                    val pref = gpuPref(activity)
                    assertEquals(expectChecked, pref.isChecked)
                    assertEquals(beforeCancel, service!!.machine)
                    assertEquals(expectChecked, service!!.gpu)
                    // Now confirm restart.
                    assertFalse(pref.onPreferenceChangeListener!!.onPreferenceChange(pref, targetValue))
                }
                clickDialogButton(expectedDialogMessage, android.R.id.button1, app.getString(R.string.restart))
            }
        }

        val intent = Intent(app, TerminalService::class.java)
        app.startForegroundService(intent)
        assertTrue(app.bindService(intent, connection, Context.BIND_AUTO_CREATE))
        try {
            assertTrue("TerminalService failed to bind", bound.await(10, TimeUnit.SECONDS))
            val s = service!!
            var m0 = awaitMachine()
            if (s.gpu) {
                instrumentation.runOnMainSync { s.setGpu(false) }
                m0 = awaitMachine(m0)
            }
            assertFalse(s.gpu)
            assertFalse(s.gpuAvailable)
            assertFalse(Native.hasGpu(m0))
            assertFalse(Diagnostics.environment(app).contains(", Vulkan GPU"))
            run(m0, CHECK_NO_GPU, "nobody")

            // Enable through Settings UI and confirm restart.
            toggleInSettings(
                expectChecked = false,
                expectSummary = app.getString(R.string.gpu_summary),
                targetValue = true,
                expectedDialogMessage = app.getString(R.string.gpu_enable_message),
            )
            val m1 = awaitMachine(m0)
            assertNotEquals(m0, m1)
            assertTrue(s.gpu)
            val enabledGpuAvailable = s.gpuAvailable
            assertEquals(Native.hasGpu(m1), enabledGpuAvailable)
            assertTrue(Diagnostics.environment(app).contains(", Vulkan GPU"))
            run(m1, "test -x /usr/local/bin/appine-gpu", "nobody")
            run(m1, if (enabledGpuAvailable) CHECK_HAS_GPU else CHECK_NO_GPU, "nobody")

            // Disable through Settings UI and confirm restart.
            val enabledSummary = app.getString(if (enabledGpuAvailable) R.string.gpu_summary else R.string.gpu_unavailable)
            toggleInSettings(
                expectChecked = true,
                expectSummary = enabledSummary,
                targetValue = false,
                expectedDialogMessage = app.getString(R.string.gpu_disable_message),
            )
            val m2 = awaitMachine(m1)
            assertNotEquals(m1, m2)
            assertFalse(s.gpu)
            assertFalse(s.gpuAvailable)
            assertFalse(Native.hasGpu(m2))
            assertFalse(Diagnostics.environment(app).contains(", Vulkan GPU"))
            run(m2, CHECK_NO_GPU, "nobody")
            reclaimed()
            Log.i("appine-gpu-test", "toggleRestartsKernel passed (gpuAvailable when enabled = $enabledGpuAvailable)")
        } finally {
            service?.let { s -> instrumentation.runOnMainSync { s.exitAll() } }
            runCatching { app.unbindService(connection) }
            prefs.edit(commit = true) {
                putBoolean("privacy_mode", previousPrivacy)
                if (hadGpu) putBoolean("gpu", previousGpu) else remove("gpu")
            }
        }
    }

    companion object {
        private const val CHECK_HAS_GPU = "test -c /dev/dri/renderD128 && test -d /sys/dev/char/226:128"
        private const val CHECK_NO_GPU = "test ! -e /dev/dri/renderD128 && test ! -d /sys/dev/char/226:128"
    }
}
