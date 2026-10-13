package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a universal run is, when the phone cannot be asked.
 *
 * This flow is the one with no shell of its own, and on this device that means no reading at all: the kernel's
 * module list is denied to app domains, `/system/bin/su` is not visible to an app even with root live, and the
 * chain's own markers never arrive because the daemon it starts becomes the KernelSU service instead of
 * returning. Waiting therefore cannot help - it reported rooted phones as failures once per run - so the chain's
 * own steps are the verdict, and this file is where that rule is decided rather than on a phone.
 *
 * The exception is the case with a shell: then the app *can* look, and silence means the run really did fail.
 */
class UniversalVerdictTest {

    @Test
    fun `with no shell, a chain whose steps landed is a root`() {
        // 2 is "the daemon was started and I stopped waiting for it" - the shape every run has here, including
        // the ones that rooted the phone.
        assertEquals(
            "a chain that patched both files and started the daemon is reported as a failure again, which is " +
                "the bug this rule exists for",
            UniversalRootRun.Verdict.RootedUnverified,
            UniversalRootRun.verdict(code = 2, reading = UniversalRootRun.Reading.Nothing, canRead = false),
        )
        assertEquals(
            "0 - the patches applied and the daemon started - is not accepted as a root",
            UniversalRootRun.Verdict.RootedUnverified,
            UniversalRootRun.verdict(code = 0, reading = UniversalRootRun.Reading.Nothing, canRead = false),
        )
    }

    @Test
    fun `with no shell, a chain that failed is still a failure`() {
        // 3 is "the patches did not land" and 1 is "the daemon exited with an error": neither is a boot that
        // could have been rooted, however blind this app is.
        assertEquals(
            "a chain whose patches did not land is being reported as rooted",
            UniversalRootRun.Verdict.Failed,
            UniversalRootRun.verdict(code = 3, reading = UniversalRootRun.Reading.Nothing, canRead = false),
        )
        assertEquals(
            "a daemon that exited with an error is being reported as root",
            UniversalRootRun.Verdict.Failed,
            UniversalRootRun.verdict(code = 1, reading = UniversalRootRun.Reading.Nothing, canRead = false),
        )
        assertEquals(
            "the chain's own failure marker is ignored",
            UniversalRootRun.Verdict.Failed,
            UniversalRootRun.verdict(code = 2, reading = UniversalRootRun.Reading.Failed, canRead = false),
        )
    }

    @Test
    fun `with a shell, silence is a failure rather than a benefit of the doubt`() {
        assertEquals(
            "a run that could have been looked at and was not found is being reported as rooted, so a daemon " +
                "that died would pass as a success",
            UniversalRootRun.Verdict.Failed,
            UniversalRootRun.verdict(code = 2, reading = UniversalRootRun.Reading.Nothing, canRead = true),
        )
    }

    @Test
    fun `the window waits for a late answer, and a zero window does not wait at all`() {
        var clock = 0L
        var reads = 0
        val lines = mutableListOf<String>()
        val late = UniversalRootRun.awaitRoot(
            code = 2,
            windowMillis = 100,
            pollMillis = 10,
            now = { clock },
            sleep = { clock += it },
            read = {
                reads++
                if (reads >= 4) UniversalRootRun.Reading.SuInstalled else UniversalRootRun.Reading.Nothing
            },
            report = { lines += it },
        )
        assertEquals(
            "an answer that arrived on the fourth poll was thrown away, which is the late-root failure itself",
            UniversalRootRun.Reading.SuInstalled,
            late,
        )
        assertEquals("the reader stopped being asked before it answered", 4, reads)
        assertEquals("the wait was not said exactly once", 1, lines.size)

        clock = 0L
        reads = 0
        val never = UniversalRootRun.awaitRoot(
            code = 2,
            windowMillis = 100,
            pollMillis = 10,
            now = { clock },
            sleep = { clock += it },
            read = { reads++; UniversalRootRun.Reading.Nothing },
        )
        assertEquals(UniversalRootRun.Reading.Nothing, never)
        assertEquals("a 100ms window answered from 11 readings and no more", 11, reads)

        // The shape the flow uses when no reading can be made at all: one look, no sleep, no window.
        clock = 0L
        reads = 0
        val unreadable = UniversalRootRun.awaitRoot(
            code = 2,
            windowMillis = 0,
            pollMillis = 10,
            now = { clock },
            sleep = { clock += it },
            read = { reads++; UniversalRootRun.Reading.Nothing },
        )
        assertEquals(UniversalRootRun.Reading.Nothing, unreadable)
        assertEquals("a zero window still polled more than once", 1, reads)
        assertEquals("a zero window slept, so a run with nothing to wait for still waits", 0L, clock)
    }

    @Test
    fun `failed or unexpected chain results read once without waiting for root`() {
        listOf(1, 3, -1, 99).forEach { code ->
            var clock = 0L
            var reads = 0
            var sleeps = 0
            val lines = mutableListOf<String>()
            val reading = UniversalRootRun.awaitRoot(
                code = code,
                windowMillis = UniversalRootRun.LATE_ROOT_WINDOW_MILLIS,
                now = { clock },
                sleep = { sleeps++; clock += it },
                read = { reads++; UniversalRootRun.Reading.Nothing },
                report = { lines += it },
            )

            assertEquals("code $code did not preserve the phone's reading", UniversalRootRun.Reading.Nothing, reading)
            assertEquals("code $code kept polling after the chain failed", 1, reads)
            assertEquals("code $code spent time waiting for a daemon it did not reach", 0, sleeps)
            assertTrue("code $code promised to wait for root after a failed chain", lines.isEmpty())
            assertEquals(
                "code $code was accepted as root without an observed root",
                UniversalRootRun.Verdict.Failed,
                UniversalRootRun.verdict(code, reading, canRead = true),
            )
        }
    }

    @Test
    fun `a patch failure still preserves an observed live root`() {
        var reads = 0
        var sleeps = 0
        val lines = mutableListOf<String>()
        val reading = UniversalRootRun.awaitRoot(
            code = 3,
            windowMillis = UniversalRootRun.LATE_ROOT_WINDOW_MILLIS,
            sleep = { sleeps++ },
            read = { reads++; UniversalRootRun.Reading.Live },
            report = { lines += it },
        )

        assertEquals(UniversalRootRun.Reading.Live, reading)
        assertEquals("the phone was not asked exactly once after the patch failure", 1, reads)
        assertEquals("an observed live root still waited", 0, sleeps)
        assertTrue("an observed live root still promised a wait", lines.isEmpty())
        assertEquals(
            "the failed chain's code overrode an observed live root",
            UniversalRootRun.Verdict.Rooted,
            UniversalRootRun.verdict(code = 3, reading = reading, canRead = true),
        )
    }

    @Test
    fun `a successful chain can wait for a late live root`() {
        var clock = 0L
        var reads = 0
        val lines = mutableListOf<String>()
        val reading = UniversalRootRun.awaitRoot(
            code = 0,
            windowMillis = 100,
            pollMillis = 10,
            now = { clock },
            sleep = { clock += it },
            read = {
                reads++
                if (reads == 3) UniversalRootRun.Reading.Live else UniversalRootRun.Reading.Nothing
            },
            report = { lines += it },
        )

        assertEquals(UniversalRootRun.Reading.Live, reading)
        assertEquals("a successful chain stopped before root became visible", 3, reads)
        assertEquals("a successful chain did not spend the two polling intervals", 20L, clock)
        assertEquals("a successful chain did not report its wait exactly once", 1, lines.size)
        assertEquals(
            UniversalRootRun.Verdict.Rooted,
            UniversalRootRun.verdict(code = 0, reading = reading, canRead = true),
        )
    }

    @Test
    fun `a reading that answered is a root, whatever the chain said`() {
        listOf(
            UniversalRootRun.Reading.Live,
            UniversalRootRun.Reading.Marker,
            UniversalRootRun.Reading.SuInstalled,
        ).forEach { reading ->
            assertEquals(
                "a reading of $reading is not being taken as a root",
                UniversalRootRun.Verdict.Rooted,
                UniversalRootRun.verdict(code = 2, reading = reading, canRead = false),
            )
        }
        assertFalse(
            "the chain's account is being stretched to cover a code no step of it produces",
            UniversalRootRun.chainReachedTheDaemon(1) || UniversalRootRun.chainReachedTheDaemon(3),
        )
        assertTrue(
            "the two codes that mean the daemon was reached are no longer accepted",
            UniversalRootRun.chainReachedTheDaemon(0) && UniversalRootRun.chainReachedTheDaemon(2),
        )
    }

    @Test
    fun `an unverified root offers the manager that can confirm it, beside the restart that finishes it`() {
        val viewModel = source("app/src/main/java/dev/busung/s25uroot/InstallViewModel.kt")
        assertTrue(
            "the unverified verdict no longer records the manager to open, so a person who cannot see the root " +
                "the run just created is given nothing to open",
            viewModel.contains("unverifiedRootManager = plan.flavor"),
        )
        assertTrue(
            "the log no longer names the manager for the flavour that was loaded, so the sentence pointing at it " +
                "has nothing to name",
            viewModel.contains("R.string.universal_confirm_in_manager, plan.flavor.label"),
        )
        val screen = source("app/src/main/java/dev/busung/s25uroot/InstallActivity.kt")
        assertTrue(
            "the run screen no longer offers to open the manager for an unverified root",
            screen.contains("KernelSuManager.open(context, manager)"),
        )
        assertTrue(
            "the soft restart is gone from the same row, so an unverified root leaves KernelSU's modules mounted " +
                "with nothing that says what puts them into a Zygote",
            screen.contains("RecoveryTool.SoftReboot"),
        )
        assertTrue(
            "both the manager and the restart claim the row's one Priority answer, so there are two loud answers " +
                "again",
            screen.contains("role = if (manager == null)"),
        )
    }

    private fun source(path: String): String {
        val direct = java.io.File(path)
        val fromRoot = java.io.File("../$path")
        return when {
            direct.isFile -> direct.readText()
            fromRoot.isFile -> fromRoot.readText()
            else -> error("no such file from the test's working directory: $path")
        }
    }
}
