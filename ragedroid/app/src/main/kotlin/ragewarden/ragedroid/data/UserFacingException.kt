package ragewarden.ragedroid.data

/**
 * A failure whose message is written for the person using the app: toasts
 * and sign-in errors show `message` as is. The text is a string resource,
 * resolved when read, so it follows the locale.
 */
open class UserFacingException(cause: Throwable? = null, private val text: () -> String) :
    IllegalStateException(null, cause) {
    override val message: String
        get() = runCatching(text).getOrElse { javaClass.simpleName }
}
