package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The generic tier's feed: one daemon per flavour, each carrying a module for several KMIs.
 *
 * The sample below is the shape the payload repository actually publishes - copied from
 * `support/kernelsu-generic.json` at the commit that first carried all three flavours - because the failure
 * this guards against is a field the writer renamed and a reader that then quietly found nothing. A feed
 * that parses into an empty list is indistinguishable from a repository that publishes no generic daemons,
 * and that is the state a phone with no entry of its own cannot tell from "your phone is not supported".
 */
class GenericDaemonFeedTest {

    private fun feed(vararg entries: String): String =
        """{"schemaVersion":1,"generic":[${entries.joinToString(",")}]}"""

    private fun entry(
        flavor: String,
        kmis: String = """["android12-5.10","android13-5.15","android14-6.1","android15-6.6"]""",
        version: String = "3.3.0",
        size: Long = 5475352,
        susfs: Boolean = false,
    ): String = """
        {"flavor":"$flavor","kmis":$kmis${
        if (susfs) ""","susfs":true""" else ""
    },"daemon":{
          "url":"https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/kernelsu/ksud-generic-kdp",
          "size":$size,
          "sha256":"f4121ed34eeb4656802f24a4d3d0f7b9eb07304f89c57ce16112027d590a2885",
          "version":"$version"}}
    """.trimIndent()

    @Test
    fun `each of the two generic rows gets its own build`() {
        val daemons = GenericDaemonFeed.parse(
            feed(
                entry("kernelsu-next"),
                entry("kernelsu-next", version = "3.4.1", susfs = true),
            ).toByteArray(),
        ).entries

        assertEquals("the flag has to survive parsing", 1, daemons.count { it.susfs })
        // The plain row stages the plain daemon and the hiding row the hiding one, whichever order a source
        // listed them in. The two are separate artifacts with separate digests, so the row a person picked is
        // the one their phone runs rather than a preference applied to the plain row on their behalf.
        assertEquals(
            "3.3.0",
            daemons.covering(KernelSuFlavor.KernelSuNext, "android15-6.6", hiding = false)?.version,
        )
        assertEquals(
            "3.4.1",
            daemons.covering(KernelSuFlavor.KernelSuNext, "android15-6.6", hiding = true)?.version,
        )
    }

    @Test
    fun `the two generic rows fall back in one direction only`() {
        // A source publishing only the hiding feed, which is the state this repository itself is in for every
        // KMI but the one it has built: the plain row stages it rather than refusing, because a daemon carrying
        // the hiding support roots a phone exactly like one that does not.
        val hidingOnly = GenericDaemonFeed.parse(feed(entry("kernelsu-next", susfs = true)).toByteArray()).entries
        assertEquals(
            "3.3.0",
            hidingOnly.covering(KernelSuFlavor.KernelSuNext, "android15-6.6", hiding = false)?.version,
        )
        // The other direction there is nothing to fall back to. The hiding row takes a daemon that carries the
        // support or none at all: handing it a plain one would be a row saying SUSFS over a run that hides
        // nothing, which is the one thing that row exists to make visible.
        val plainOnly = GenericDaemonFeed.parse(feed(entry("kernelsu-next")).toByteArray()).entries
        assertNull(plainOnly.covering(KernelSuFlavor.KernelSuNext, "android15-6.6", hiding = true))
    }

    @Test
    fun `the published shape parses into what the run needs`() {
        val parsed = GenericDaemonFeed.parse(feed(entry("kernelsu")).toByteArray())

        assertEquals(1, parsed.schemaVersion)
        assertEquals(1, parsed.entries.size)
        val daemon = parsed.entries.single()
        assertEquals(KernelSuFlavor.KernelSu, daemon.flavor)
        assertEquals(
            setOf("android12-5.10", "android13-5.15", "android14-6.1", "android15-6.6"),
            daemon.kmis,
        )
        assertEquals(5475352L, daemon.daemon.size)
        assertEquals("3.3.0", daemon.version)
        assertTrue(daemon.daemon.url.endsWith("/kernelsu/ksud-generic-kdp"))
        assertTrue("the digest has to survive parsing, it is what the download is checked against", daemon.daemon.sha256 != null)
    }

    @Test
    fun `a version written as a tag is read as the release`() {
        // The pair publish writes the run's ref, so `v3.4.0` and `3.4.0` are both in the wild, and the manager
        // rows compare this against a manager's own versionName. A leading `v` left on would match nothing.
        val parsed = GenericDaemonFeed.parse(feed(entry("kernelsu-next", version = "v3.4.0")).toByteArray())
        assertEquals("3.4.0", parsed.entries.single().version)
    }

    @Test
    fun `a pre-release keeps its suffix`() {
        // ReSukiSU publishes rc tags and there is no plain `4.2.0` to look up, so the suffix is part of the
        // release's name rather than a description of it.
        val parsed = GenericDaemonFeed.parse(feed(entry("resukisu", version = "v4.2.0-rc3")).toByteArray())
        assertEquals("4.2.0-rc3", parsed.entries.single().version)
    }

    @Test
    fun `a flavour this build does not know is dropped and named`() {
        // Never read as the default: installing the other project's KernelSU because a name looked close is
        // the one outcome nobody can explain afterwards.
        val parsed = GenericDaemonFeed.parse(
            feed(entry("kernelsu"), entry("kernel-su")).toByteArray(),
        )
        assertEquals(listOf(KernelSuFlavor.KernelSu), parsed.entries.map { it.flavor })
        assertEquals(listOf("kernel-su"), parsed.ignored)
    }

    @Test
    fun `a daemon carrying no KMI is not an entry`() {
        // An entry with an empty `kmis` can serve no phone at all, so keeping it would only produce a tier
        // that looks available and refuses every device.
        val parsed = GenericDaemonFeed.parse(feed(entry("kernelsu", kmis = "[]")).toByteArray())
        assertEquals(emptyList<GenericDaemon>(), parsed.entries)
    }

    @Test
    fun `another schema is refused rather than half-read`() {
        val wrong = """{"schemaVersion":2,"generic":[]}""".toByteArray()
        val failure = runCatching { GenericDaemonFeed.parse(wrong) }.exceptionOrNull()
        assertTrue(
            "a feed written for a later schema has to be refused, not read for the fields that happen to " +
                "be called the same: $failure",
            failure is IllegalArgumentException,
        )
    }

    @Test
    fun `only the flavours with a hiding daemon for this kernel are covered`() {
        // What the sheet asks, one tier up from `covering` and with the same rule behind it: the flavour whose
        // hiding daemon carries this KMI counts, the one whose daemon carries another kernel does not, and
        // neither does a flavour with no hiding daemon at all.
        val daemons = GenericDaemonFeed.parse(
            feed(
                entry("kernelsu-next", susfs = true),
                entry("kernelsu", kmis = """["android14-6.1"]""", susfs = true),
                entry("resukisu"),
            ).toByteArray(),
        ).entries

        assertEquals(setOf(KernelSuFlavor.KernelSuNext), daemons.hidingFlavorsFor("android15-6.6"))
        // A kernel that could not be read covers nothing, and the caller has to tell that from a feed nobody
        // published: the answer is empty either way, and only the caller knows whether it did the reading.
        assertEquals(emptySet<KernelSuFlavor>(), daemons.hidingFlavorsFor(null))
    }

    @Test
    fun `the KMI decides, and a miss is a miss`() {
        val daemons = GenericDaemonFeed.parse(
            feed(entry("kernelsu"), entry("resukisu", kmis = """["android14-6.1"]"""))
                .toByteArray(),
        ).entries

        assertEquals(
            KernelSuFlavor.KernelSu,
            daemons.covering(KernelSuFlavor.KernelSu, "android15-6.6", hiding = false)?.flavor,
        )
        // The same phone asking for the other flavour gets the daemon that carries its KMI...
        assertEquals(
            KernelSuFlavor.ReSukiSU,
            daemons.covering(KernelSuFlavor.ReSukiSU, "android14-6.1", hiding = false)?.flavor,
        )
        // ...and nothing at all when the flavour's daemon carries a different family. A null here is what
        // makes the run refuse rather than load a module for somebody else's kernel.
        assertNull(daemons.covering(KernelSuFlavor.ReSukiSU, "android15-6.6", hiding = false))
        assertNull(
            "a device whose KMI could not be read covers nothing",
            daemons.covering(KernelSuFlavor.KernelSu, null, hiding = false),
        )
        assertNull(
            "an unpublished flavour is not filled in from another",
            daemons.covering(KernelSuFlavor.KernelSuNext, "android15-6.6", hiding = false),
        )
    }
}
