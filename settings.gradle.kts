pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version "8.7.3"
        id("com.android.application") version "8.7.3"
        id("org.jetbrains.kotlin.android") version "2.1.20"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ForgeStore"
include(
    ":library",
    ":module",
    ":service",
    ":stub"
)