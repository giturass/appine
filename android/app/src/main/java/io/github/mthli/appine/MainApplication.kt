package io.github.mthli.appine

import android.app.Application

/** Initializes app-wide components when the process starts. */
class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (getProcessName() == "$packageName:venus") return
        GpuService.app = this
        Privacy.install(this)
        Diagnostics.install(this)
    }
}
