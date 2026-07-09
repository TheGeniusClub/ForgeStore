plugins {
    id("com.android.library")
}

dependencies {
    compileOnly("androidx.annotation:annotation:1.9.1")
}

android {
    namespace = "service.stub"
    buildToolsVersion = "36.0.0"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}