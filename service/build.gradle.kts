plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

dependencies {
    compileOnly("androidx.annotation:annotation:1.9.1")
    compileOnly(project(":stub"))
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
}

val verName: String by rootProject.extra
val verCode: Int by rootProject.extra

android {
    namespace = "com.dere3046.forgestore"
    buildToolsVersion = "36.0.0"
    ndkVersion = "25.1.8937393"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
        targetSdk = 36
        versionCode = verCode
        versionName = verName
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            vcsInfo.include = false
            proguardFiles("proguard-rules.pro")
            signingConfig = android.signingConfigs.getByName("debug")
        }
    }

    packaging {
        resources {
            excludes += setOf(
                "kotlin/**",
                "META-INF/**",
                "org/**",
                "kotlin-tooling-metadata.json"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }

    dependenciesInfo {
        includeInApk = false
    }

    tasks.withType<JavaCompile> {
        options.compilerArgs.add("-Xlint:deprecation")
        options.compilerArgs.add("-Xlint:unchecked")
        options.compilerArgs.add("-Xdiags:verbose")
    }
}