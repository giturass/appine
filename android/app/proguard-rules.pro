# Keep the complete app JNI interface, including console methods used only by instrumentation.
-keepclasseswithmembers,includedescriptorclasses class io.github.mthli.appine.* {
    native <methods>;
}

# The native terminal pump looks these up by name and JVM descriptor (hosts/android/src/vt.rs).
-keepclassmembers class io.github.mthli.appine.VtSession {
    public void on*(...);
}

-keep class io.github.mthli.appine.GpuService { *; }
-keep class io.github.mthli.appine.GpuConnection { public void close(); }
