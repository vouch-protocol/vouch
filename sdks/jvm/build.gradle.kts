plugins {
    `java-library`
    `maven-publish`
    signing
    kotlin("jvm") version "1.9.24"
}

group = "com.vouchprotocol"
version = "0.1.0"
description = "Vouch Protocol JVM SDK (Kotlin + Java) over the canonical Rust core via JNA / UniFFI."

repositories { mavenCentral() }

dependencies {
    // JNA loads the native core. The Java SDK (com.vouchprotocol.core.Vouch)
    // calls the cbindgen C ABI; the bundled UniFFI Kotlin binding (vouch_core.kt)
    // uses JNA and kotlinx-coroutines, for Kotlin users who prefer it.
    api("net.java.dev.jna:jna:5.14.0")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
    withSourcesJar()
    withJavadocJar()
}

// During development the native lib lives in lib/; in the packaged jar it is
// bundled under src/main/resources/<jna-platform>/ so JNA finds it on the
// classpath. Tests point JNA at lib/ explicitly.
tasks.test {
    useJUnitPlatform()
    systemProperty("jna.library.path", file("lib").absolutePath)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "vouch-core"
            from(components["java"])
            pom {
                name.set("Vouch Protocol JVM SDK")
                description.set("Verify and sign Vouch credentials on the JVM (Kotlin + Java) over the canonical Rust core.")
                url.set("https://vouch-protocol.com")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("ramprasad-gaddam")
                        name.set("Ramprasad Anandam Gaddam")
                    }
                }
                scm {
                    url.set("https://github.com/vouch-protocol/vouch")
                    connection.set("scm:git:https://github.com/vouch-protocol/vouch.git")
                }
            }
        }
    }
    repositories {
        maven {
            name = "central"
            // Set centralUrl / centralUsername / centralPassword (Maven Central
            // Portal credentials) in ~/.gradle/gradle.properties to publish.
            url = uri(providers.gradleProperty("centralUrl").getOrElse("https://central.sonatype.com/api/v1/publisher"))
            credentials {
                username = providers.gradleProperty("centralUsername").orNull
                password = providers.gradleProperty("centralPassword").orNull
            }
        }
    }
}

signing {
    // Only sign when a signing key is configured, so local builds and tests do
    // not require GPG keys. Configure signing.keyId / signing.password /
    // signing.secretKeyRingFile (or use-gpg-cmd) to sign for release.
    isRequired = providers.gradleProperty("signing.keyId").isPresent
    sign(publishing.publications["maven"])
}
