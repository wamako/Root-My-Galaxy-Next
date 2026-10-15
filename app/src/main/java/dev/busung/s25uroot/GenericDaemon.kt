package dev.busung.s25uroot

import org.json.JSONArray
import org.json.JSONObject

/**
 * A daemon that carries a kernel module for several KMIs instead of one.
 *
 * ## Why this is a separate tier rather than another payload
 *
 * A payload entry in `targets-v3.json` is a *device*: it names the models and kernel releases it was built
 * and tested for, and its `kernelsu` artifact is a daemon embedding the module built for that one kernel
 * release. That is the strongest pairing available and it stays the first choice.
 *
 * This is the other half of the story. `ksud` loads its kernel module out of its **own asset directory**,
 * asking for `<kmi>_kernelsu.ko` after working out the running kernel's KMI - so one daemon carrying a
 * module per KMI serves every device whose KMI is in that set, whatever model it is and whatever exact
 * kernel release it runs. The payload repository builds one per flavour
 * (`support/kernelsu-generic.json`) and this is what the app reads.
 *
 * ## What it does not replace
 *
 * The per-device entry, and never silently: a device entry's module was built for the release that device
 * runs, and the generic one was not - it relies on the daemon rewriting `vermagic` to whatever the kernel
 * requires before it retries `init_module`. So the two are offered as a choice, with what each one is, and
 * neither is used for the other's device behind the user's back. See [PayloadTier].
 *
 * ## Why the KMI is matched rather than assumed
 *
 * [kmis] is read out of the daemon's own asset table by the payload repository when it is published, so it
 * is what the binary actually carries rather than what a file name says. A phone whose KMI is not in it is
 * refused with that said out loud, because the alternative - handing it a module for another kernel - is
 * refused by the loader with nothing anywhere to explain why the run did nothing.
 */
data class GenericDaemon(
    val flavor: KernelSuFlavor,
    /** The KMIs this daemon carries a module for, as its own asset table lists them. */
    val kmis: Set<String>,
    val daemon: RemoteArtifact,
    /** The KernelSU release the daemon was built from, when the feed says. */
    val version: String?,
    /**
     * Whether this daemon was built with the hiding tier compiled in, as its feed declares.
     *
     * A property of the artifact, not of the file it was read from: a daemon that carries susfs roots the
     * phone exactly like one that does not, and additionally hides - so where both are published for a
     * KMI, this is what lets `covering()` hand each of the two generic rows its own build.
     */
    val susfs: Boolean = false,
    val sourceId: String = "",
    val sourceLabel: String = "",
    val sourceCommit: String = "",
) {
    /** Whether this daemon has a module for [kmi]. A null KMI is never covered. */
    fun covers(kmi: String?): Boolean = kmi != null && kmi in kmis

    /** What this covers, for a log line or a dialog. */
    val coverage: String
        get() = kmis.sorted().joinToString(", ")
}

/**
 * The generic tier, as the payload repository publishes it.
 *
 * One entry per flavour. Separate from [SupportManifest] on purpose: that one is a released client
 * contract whose entries name a tested artifact per device, and this is a fallback that is allowed to be
 * less specific. Nothing here can change what a device's own entry points at.
 */
data class GenericDaemonFeed(
    val schemaVersion: Int,
    val entries: List<GenericDaemon>,
    /** Flavour ids this build does not know, dropped rather than read as the default. */
    val ignored: List<String> = emptyList(),
) {
    companion object {
        /** Where a payload repository keeps it, beside the manifest it is read from. */
        const val PATH = "support/kernelsu-generic.json"

        /**
         * The same tier, built with the hiding support compiled in.
         *
         * A second file rather than more entries in [PATH], and that is upstream's own arrangement, not
         * this app's: that feed holds one entry per flavour, so a hiding daemon listed there would replace
         * the plain one for every phone in the KMI. A source that does not publish this file is the normal
         * case for every repository except the one this fork ships, so a missing file is not a failure -
         * see `PayloadRepository.loadGenericDaemons()`.
         */
        const val SUSFS_PATH = "support/kernelsu-generic-susfs.json"

        /** The only shape this build reads. A different one is a feed written for a different app. */
        const val SUPPORTED_SCHEMA = 1

        /**
         * Reads a feed.
         *
         * An entry naming an unknown flavour is dropped, not defaulted - the same rule the device manifest
         * follows, and for the same reason: installing the other project's KernelSU because a name looked
         * close is the one outcome nobody can explain afterwards. What was dropped is returned so the
         * caller can say so.
         */
        fun parse(bytes: ByteArray): GenericDaemonFeed {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            val schemaVersion = root.optInt("schemaVersion", 0)
            require(schemaVersion == SUPPORTED_SCHEMA) {
                "Unsupported generic daemon feed schema $schemaVersion"
            }

            val entriesJson = root.optJSONArray("generic") ?: JSONArray()
            val ignored = mutableListOf<String>()
            val entries = buildList {
                for (index in 0 until entriesJson.length()) {
                    val entry = entriesJson.getJSONObject(index)
                    val flavor = entry.flavorOrNull()
                    if (flavor == null) {
                        ignored += entry.optString("flavor").trim()
                        continue
                    }
                    // A daemon with no KMI covers nothing, so there is no device it could be offered to.
                    val kmis = entry.optJSONArray("kmis").strings()
                    if (kmis.isEmpty()) continue
                    val daemon = entry.getJSONObject("daemon")
                    add(
                        GenericDaemon(
                            flavor = flavor,
                            kmis = kmis,
                            daemon = daemon.artifact(),
                            version = daemon.declaredVersion(),
                            // Declared by the feed rather than inferred from which file it was read out of,
                            // because a source is free to publish the same daemon from either path.
                            susfs = entry.optBoolean("susfs", false),
                        ),
                    )
                }
            }
            return GenericDaemonFeed(schemaVersion, entries, ignored)
        }

        private fun JSONArray?.strings(): Set<String> = buildSet {
            if (this@strings == null) return@buildSet
            for (index in 0 until length()) add(getString(index).trim())
        }
    }
}

/**
 * The generic daemon for [flavor] that carries a module for [kmi], or null when there is none.
 *
 * A phone whose KMI no entry covers gets null and is told which KMIs there were, rather than being handed
 * a daemon that would fail at `finit_module`.
 *
 * [hiding] is which of the two generic tiers is asking, and the two are not symmetrical:
 *
 * - the plain tier takes a daemon that does not carry the hiding support, and falls back to one that does
 *   when that is all a source publishes for this kernel. The fallback is not a silent upgrade of the run -
 *   a hiding daemon roots the phone exactly like a plain one, so it cannot lead somewhere the row did not
 *   promise - and it is what keeps a phone whose source publishes only the second feed rootable at all.
 * - the hiding tier takes **only** a daemon that carries the support. Handing it a plain one would be a row
 *   saying "susfs" over a run that hides nothing, which is the single thing that row exists to make
 *   visible, so there is no fallback and the run refuses instead.
 */
internal fun List<GenericDaemon>.covering(
    flavor: KernelSuFlavor,
    kmi: String?,
    hiding: Boolean,
): GenericDaemon? {
    val forKernel = filter { it.flavor == flavor && it.covers(kmi) }
    return if (hiding) {
        forKernel.firstOrNull { it.susfs }
    } else {
        forKernel.firstOrNull { !it.susfs } ?: forKernel.firstOrNull()
    }
}

/**
 * The flavours the read sources publish a hiding daemon for, of the ones that carry a module for [kmi].
 *
 * The payload sheet's question about the hiding tier, and answered with the same call the run makes
 * ([covering]) rather than a comparison of its own: a flavour left out of this set is a flavour whose row
 * could only lead to the run's own refusal, which is the tap the row exists to save.
 *
 * A null [kmi] covers nothing, so the answer is empty and the caller has to tell that from a read it never
 * made - the reading itself, and what an unread kernel means, belong to whoever did the reading.
 */
internal fun List<GenericDaemon>.hidingFlavorsFor(kmi: String?): Set<KernelSuFlavor> =
    KernelSuFlavor.entries.filterTo(mutableSetOf()) { covering(it, kmi, hiding = true) != null }
