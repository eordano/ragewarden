package ragewarden.ragedroid.identities

import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.uiString

/**
 * A PIV slot's touch policy as the card reports it: GET METADATA, INS 0xF7,
 * which yubikit sends from `getSlotMetadata` -- the read rageterm does with its
 * own APDU. Only ALWAYS makes every private-key operation wait for a finger:
 * CACHED lets one touch cover about 15 seconds of further uses, and DEFAULT
 * means never.
 */
internal sealed interface SlotTouch {
    data object Always : SlotTouch

    /** NEVER, DEFAULT, CACHED, or a policy byte yubikit does not know. */
    data class Weaker(val policy: String) : SlotTouch

    /**
     * The card has no GET METADATA: YubiKey firmware before 5.3, or a PIV
     * applet that is not Yubico's. It says nothing either way.
     */
    data object Unreadable : SlotTouch

    companion object {
        fun read(piv: PivSession, slot: Slot): SlotTouch = try {
            val policy = piv.getSlotMetadata(slot).touchPolicy
            if (policy == TouchPolicy.ALWAYS) Always else Weaker(policy.name.lowercase())
        } catch (e: UnsupportedOperationException) {
            Unreadable
        } catch (e: ApduException) {
            Unreadable
        } catch (e: IllegalArgumentException) {
            Weaker("0x??")
        }
    }
}

/**
 * A slot whose touch policy is not ALWAYS. Refused at enrolment and before
 * every unwrap, before the PIN is sent: such a slot would decrypt for anyone
 * holding the key and its PIN, with no touch.
 */
class PivTouchPolicyException(keyLabel: String, slot: Slot, policy: String) :
    HardwareTapException(uiString(R.string.piv_touch_policy_refused, keyLabel, "%02x".format(slot.value), policy)) {
    override val retryable: Boolean get() = false
}
