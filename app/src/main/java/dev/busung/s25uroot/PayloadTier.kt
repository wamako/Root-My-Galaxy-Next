package dev.busung.s25uroot

/**
 * Which daemon a universal-root run stages, asked for after the flavour rather than assumed.
 *
 * The flavour answers *which* KernelSU; this answers *which build of it*. Both are real choices with
 * different trade-offs, and the app cannot make this one for the user:
 *
 * - [Device] is the feed's entry for this exact phone. Its kernel module was built for the kernel release
 *   this phone runs and the artifact is the one that device was tested with, so it is the strongest pairing
 *   the repository can publish and it only exists for phones somebody has ported.
 * - [Generic] is the KMI-generic daemon for the same flavour: one artifact carrying a module per KMI, which
 *   covers every phone whose kernel belongs to that family. It exists for phones with no entry of their own,
 *   and it is what makes this path useful on a device nobody has ported yet.
 * - [Susfs] is that same generic daemon built with the hiding support compiled in, which a source publishes
 *   as a second feed. It roots the phone exactly as the generic one does and additionally hides what the
 *   kernel is asked about; it is a row of its own rather than a preference the app applies to [Generic],
 *   because which of the two a phone ends up running is not a detail the person choosing can be left to
 *   find out from the log.
 *
 * The reason this is a question rather than a preference the app guesses at: the two produce visibly
 * different runs. A generic run loads a module that was not built for the phone's own release and relies on
 * the daemon's `vermagic` rewrite to get it in, and a device run may load nothing at all if the feed has no
 * entry for this phone. Which one was used changes what a log means, so the run says which one it was rather
 * than leaving two outcomes looking alike.
 *
 * There is deliberately no "try one, then the other" mode. A failed load patches the kernel and leaves a
 * marker only a reboot clears, so a fallback inside one run would be a second load into a kernel that is
 * already partly patched the run is refused in that state, not retried.
 */
enum class PayloadTier {
    /** The payload entry for this exact device, built for the kernel release it runs. */
    Device,

    /** The KMI-generic daemon for the chosen flavour, covering a family of kernels. */
    Generic,

    /**
     * The KMI-generic daemon for the chosen flavour, built with the hiding support compiled in.
     *
     * A tier rather than a flag on [Generic] for the reason the app has tiers at all: the two stage
     * different artifacts with different sizes and different digests, a run reports which one it used, and a
     * boot run stages the one it recorded. A source that publishes no hiding daemon for this phone's kernel
     * is not a fallback - this row refuses, and says so, rather than quietly running the plain one under a
     * word that promised otherwise.
     */
    Susfs,
    ;

    companion object {
        /** The tier an id names, or null when this build does not know it. */
        fun fromId(id: String): PayloadTier? = entries.firstOrNull { it.name.equals(id, ignoreCase = true) }

        /** The ids this build accepts, for a message that has to name what it knows. */
        val ids: List<String> get() = entries.map { it.name }
    }
}
