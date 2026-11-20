package io.github.mthli.appine

import android.content.Intent
import android.os.Build
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises cold activity startup and its system-bar controller. */
@RunWith(AndroidJUnit4::class)
class MainActivityTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun coldLaunchCreatesDecorAndInsetsController() {
        assumeTrue(Build.VERSION.SDK_INT >= 35)
        // MainActivity is singleTask, so clear its task to exercise onCreate rather than onNewIntent.
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ActivityScenario.launch<MainActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                assertNotNull("MainActivity must create its decor during onCreate", activity.window.peekDecorView())
                assertNotNull("MainActivity must expose its system-bar controller after onCreate", activity.window.insetsController)
            }
        }
    }
}
