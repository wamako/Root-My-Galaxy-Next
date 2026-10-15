package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The tier crosses a process boundary as a string, so reading it back has to be exact.
 *
 * The card puts the answer on an intent and the install screen reads it; the screen also has to survive an
 * answer it cannot read, because a launch from a notification or from somewhere that predates this question
 * still has to root a phone rather than do nothing.
 */
class PayloadTierTest {

    @Test
    fun `every tier survives the round trip the intent makes`() {
        for (tier in PayloadTier.entries) {
            assertEquals(tier, PayloadTier.fromId(tier.name))
        }
    }

    @Test
    fun `an id this build does not know is not a tier`() {
        // The caller falls back to the device tier, which is the one that refuses rather than the one that
        // loads a module built for another phone - so an unreadable answer is the safe direction.
        assertNull(PayloadTier.fromId(""))
        assertNull(PayloadTier.fromId("device-specific"))
        assertNull(PayloadTier.fromId("generic\n"))
        assertNull(PayloadTier.fromId("DEVICE "))
    }

    @Test
    fun `the ids are listed for a message that has to name them`() {
        assertEquals(listOf("Device", "Generic", "Susfs"), PayloadTier.ids)
    }
}
