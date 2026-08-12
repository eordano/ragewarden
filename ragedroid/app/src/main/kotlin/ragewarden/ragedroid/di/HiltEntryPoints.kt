package ragewarden.ragedroid.di

import android.content.Context
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.HistoryStore
import ragewarden.ragedroid.data.LockPolicy
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.RotationTracker
import ragewarden.ragedroid.data.audit.AuditFeed

@EntryPoint
@InstallIn(SingletonComponent::class)
interface AppEntryPoint {
    fun recipientStore(): RecipientStore
    fun bitwardenRepo(): BitwardenVaultRepository
    fun lockPolicy(): LockPolicy
    fun lockState(): LockState
    fun auditFeed(): AuditFeed
    fun rotationTracker(): RotationTracker
    fun historyStore(): HistoryStore
}

fun Context.appEntryPoint(): AppEntryPoint =
    EntryPointAccessors.fromApplication(applicationContext, AppEntryPoint::class.java)
