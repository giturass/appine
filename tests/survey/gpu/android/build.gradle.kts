plugins { id("com.android.application") version "9.4.1" }

android {
    namespace = "io.github.mthli.appine.gpuprobe"
    compileSdk = 37
    ndkVersion = "29.0.14206865"
    defaultConfig {
        minSdk = 30
        targetSdk = 37
        ndk { abiFilters += "arm64-v8a" }
    }
    externalNativeBuild {
        cmake { path = file("CMakeLists.txt"); version = "3.22.1" }
    }
}
