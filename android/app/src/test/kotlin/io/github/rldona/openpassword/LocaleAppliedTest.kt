package io.github.rldona.openpassword

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The per-app language only reaches a context that asks for it. On Android 12 and below that
 * means overriding it by hand, and forgetting one screen shows it in the device language, which
 * is exactly the bug this guards against.
 */
class LocaleAppliedTest {
    private val root = File("src/main/kotlin")

    private fun sources() = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    @Test
    fun `every activity applies the chosen language`() {
        val activities = sources().filter { source ->
            Regex(""":\s*(ComponentActivity|Activity)\(\)""").containsMatchIn(source.readText())
        }
        assertTrue("no activities found: ${root.absolutePath}", activities.isNotEmpty())
        for (file in activities) {
            assertTrue(
                "${file.path} extends an Activity but does not override attachBaseContext",
                file.readText().contains("override fun attachBaseContext("),
            )
        }
    }

    @Test
    fun `the autofill service applies the chosen language`() {
        val services = sources().filter { it.readText().contains(": AutofillService()") }
        assertTrue("autofill service not found", services.isNotEmpty())
        for (file in services) {
            val text = file.readText()
            assertTrue("${file.path} does not wrap its context: AppLocales.wrap", text.contains("AppLocales.wrap("))
        }
    }

    @Test
    fun `no formatter is built with a hardcoded Spanish locale`() {
        for (file in sources()) {
            val text = file.readText()
            assertFalse(
                "${file.path} pins the Spanish locale instead of using the current one",
                text.contains("forLanguageTag(\"es\")") || text.contains("Locale(\"es\")"),
            )
        }
    }
}
