package ragewarden.ragedroid.ui

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Test
import ragewarden.ragedroid.ui.screens.TapFailureKind
import ragewarden.ragedroid.ui.screens.classifyTapFailure

class TapFailureClassificationTest {
    @Test
    fun unrelated_failures_are_not_reported_as_the_wrong_key() {
        assertEquals(TapFailureKind.Unknown, classifyTapFailure(IOException("network unreachable")))
        assertEquals(TapFailureKind.Unknown, classifyTapFailure(IllegalStateException("parse: corrupt blob")))
        assertEquals(TapFailureKind.Cancelled, classifyTapFailure(RuntimeException("user cancelled")))
        assertEquals(TapFailureKind.NoMatch, classifyTapFailure(RuntimeException("decrypt: no matching identity")))
        assertEquals(TapFailureKind.WrongKey, classifyTapFailure(RuntimeException("unwrap failed for stanza")))
    }
}
