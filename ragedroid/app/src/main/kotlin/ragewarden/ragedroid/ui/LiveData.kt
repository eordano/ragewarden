package ragewarden.ragedroid.ui

import androidx.compose.runtime.compositionLocalOf
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import ragewarden.ragedroid.model.Recipient

val LocalLiveRecipients = compositionLocalOf<ImmutableList<Recipient>> { persistentListOf() }
