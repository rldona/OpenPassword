package io.github.rldona.openpassword

import io.github.rldona.openpassword.security.AvailabilityCheck
import io.github.rldona.openpassword.security.availabilityCheckFor
import org.junit.Assert.assertEquals
import org.junit.Test

class BiometricsTest {
    @Test
    fun android9UsesFingerprintManager() {
        assertEquals(AvailabilityCheck.Fingerprint, availabilityCheckFor(28))
    }

    @Test
    fun android10UsesManagerWithoutAuthenticators() {
        assertEquals(AvailabilityCheck.ManagerLegacy, availabilityCheckFor(29))
    }

    @Test
    fun android11AndLaterUseStrongAuthenticator() {
        assertEquals(AvailabilityCheck.ManagerStrong, availabilityCheckFor(30))
        assertEquals(AvailabilityCheck.ManagerStrong, availabilityCheckFor(36))
    }
}
