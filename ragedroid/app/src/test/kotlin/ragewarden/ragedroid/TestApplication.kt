package ragewarden.ragedroid

import android.app.Application
import ragewarden.ragedroid.ui.UiStrings

/**
 * The Robolectric application: a plain Application (no Hilt graph, no JNI),
 * plus the one thing every UI path needs, the string resolver.
 */
class TestApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        UiStrings.install(this)
    }
}
