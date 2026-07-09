plugins {
    id("com.android.application")
}

val verName: String by rootProject.extra
val verCode: Int by rootProject.extra

android {
    namespace = "library.stub"
    ndkVersion = "25.1.8937393"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }
}