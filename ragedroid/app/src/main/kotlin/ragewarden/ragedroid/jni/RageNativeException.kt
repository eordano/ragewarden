package ragewarden.ragedroid.jni

open class RageNativeException(message: String) : RuntimeException(message) {
    class MalformedStanza(message: String) : RageNativeException(message)

    class AeadFailure(message: String) : RageNativeException(message)

    class IdentityMissing(message: String) : RageNativeException(message)

    class Internal(message: String) : RageNativeException(message)
}
