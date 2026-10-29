package ragewarden.ragedroid.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import java.time.Clock
import ragewarden.ragedroid.data.LockPolicy
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.SessionStore

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideRecipientStore(@ApplicationContext context: Context): RecipientStore =
        RecipientStore(context)

    @Provides
    @Singleton
    fun provideSessionStore(@ApplicationContext context: Context): SessionStore =
        SessionStore(context)

    @Provides
    @Singleton
    fun provideKdfPinStore(@ApplicationContext context: Context): ragewarden.ragedroid.data.KdfPinStore =
        ragewarden.ragedroid.data.KdfPinStore(context)

    /**
     * One lock per process, shared by the UI, the IME and the autofill service.
     * Bound here rather than with `@Inject constructor` so `hasSession` stays a
     * plain lambda that a unit test can supply without an AndroidKeyStore.
     */
    @Provides
    @Singleton
    fun provideLockState(
        @ApplicationContext context: Context,
        policy: LockPolicy,
        sessionStore: SessionStore,
    ): LockState = LockState(
        context,
        policy,
        sessionNeedsUnlock = { !ragewarden.ragedroid.data.SessionBlobs.hasKeys(sessionStore.load()) },
        hasSession = { sessionStore.has() },
    )

    @Provides
    fun provideClock(): Clock = Clock.systemDefaultZone()
}
