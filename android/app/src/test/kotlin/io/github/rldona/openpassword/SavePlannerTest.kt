package io.github.rldona.openpassword

import io.github.rldona.openpassword.autofill.FillTarget
import io.github.rldona.openpassword.autofill.LoginMatcher
import io.github.rldona.openpassword.autofill.SavePlan
import io.github.rldona.openpassword.autofill.SavePlanner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SavePlannerTest {
    @Test
    fun sameUsernameUpdatesTheExistingLogin() {
        val candidates = listOf("a" to "otro@ejemplo.com", "b" to "Raul@Ejemplo.com ")
        assertEquals(SavePlan.Update("b"), SavePlanner.plan(candidates, "raul@ejemplo.com"))
    }

    @Test
    fun differentOrMissingUsernameCreatesANewLogin() {
        assertEquals(SavePlan.New, SavePlanner.plan(listOf("a" to "otro"), "raul"))
        assertEquals(SavePlan.New, SavePlanner.plan(emptyList(), "raul"))
        assertEquals(SavePlan.New, SavePlanner.plan(listOf("a" to null), "raul"))
    }

    @Test
    fun emptyUsernameMatchesALoginWithoutUsername() {
        assertEquals(SavePlan.Update("a"), SavePlanner.plan(listOf("a" to ""), ""))
    }

    @Test
    fun savedUrlsMatchTheirTargetAgain() {
        val web = FillTarget.Web("accounts.google.com")
        val app = FillTarget.App("com.example.banco")
        assertEquals("https://accounts.google.com", SavePlanner.urlFor(web))
        assertTrue(LoginMatcher.matches(listOf(SavePlanner.urlFor(web)), web))
        assertTrue(LoginMatcher.matches(listOf(SavePlanner.urlFor(app)), app))
    }
}
