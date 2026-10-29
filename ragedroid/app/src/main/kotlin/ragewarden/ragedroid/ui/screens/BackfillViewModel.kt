package ragewarden.ragedroid.ui.screens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.RotationTracker
import ragewarden.ragedroid.model.VaultItem

@HiltViewModel
class BackfillViewModel @Inject constructor(
    private val repo: BitwardenVaultRepository,
    private val rotationTracker: RotationTracker,
) : ViewModel() {

    data class State(
        val candidates: List<VaultItem> = emptyList(),
        val total: Int = 0,
        val processed: Int = 0,
        val currentName: String? = null,
        val failed: List<Pair<String, String>> = emptyList(),
        val running: Boolean = false,
        val complete: Boolean = false,
        val staleRageItemCount: Int = 0,
        val rewrapping: Boolean = false,
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    fun loadCandidates() {
        val all = repo.snapshot()
        val items = all.filter { !it.rage }
        val staleRage = repo.staleProtectedItems().size
        _state.update {
            it.copy(
                candidates = items,
                total = items.size,
                processed = 0,
                failed = emptyList(),
                currentName = null,
                running = false,
                complete = false,
                staleRageItemCount = staleRage,
            )
        }
    }

    fun start() {
        if (_state.value.running) return
        viewModelScope.launch {
            val items = _state.value.candidates
            _state.update {
                it.copy(
                    running = true,
                    processed = 0,
                    total = items.size,
                    failed = emptyList(),
                    complete = false,
                )
            }
            for (item in items) {
                _state.update { it.copy(currentName = item.name) }
                val result = runCatching {
                    val pt = repo.decrypt(item.id, emptyList(), null).getOrThrow()
                    repo.update(item.copy(rage = true), pt).getOrThrow()
                }
                _state.update { current ->
                    val failed = if (result.isFailure) {
                        current.failed + (item.id to (result.exceptionOrNull()?.message ?: "unknown"))
                    } else {
                        current.failed
                    }
                    current.copy(processed = current.processed + 1, failed = failed)
                }
            }
            _state.update { it.copy(running = false, complete = true, currentName = null) }
            if (_state.value.failed.isEmpty()) {
                rotationTracker.markFresh(repo.accountId)
            }
        }
    }

    /**
     * Re-encrypts every stale protected item to the current recipients, one
     * hardware tap each: [open] runs the tap ceremony and hands the item's
     * identities to [BitwardenVaultRepository.rewrap].
     */
    fun rewrapStale(open: suspend (VaultItem) -> Unit) {
        if (_state.value.running) return
        viewModelScope.launch {
            val items = repo.staleProtectedItems()
            _state.update {
                it.copy(running = true, rewrapping = true, processed = 0, total = items.size, failed = emptyList(), complete = false)
            }
            rewrapAll(items, open) { name, processed, failed ->
                _state.update { it.copy(currentName = name, processed = processed, failed = failed) }
            }
            _state.update { it.copy(running = false, complete = true, currentName = null, staleRageItemCount = repo.staleProtectedItems().size) }
        }
    }

    fun markRotationFresh() {
        rotationTracker.markFresh(repo.accountId)
        _state.update { it.copy(staleRageItemCount = 0) }
    }
}

/**
 * Re-encrypts [items] one at a time through [open], carrying on past a
 * failure (a declined tap, a missing key) so one item cannot strand the rest.
 */
internal suspend fun rewrapAll(
    items: List<VaultItem>,
    open: suspend (VaultItem) -> Unit,
    progress: (current: String?, processed: Int, failed: List<Pair<String, String>>) -> Unit,
) {
    var failed = emptyList<Pair<String, String>>()
    items.forEachIndexed { i, item ->
        progress(item.name, i, failed)
        runCatching { open(item) }.onFailure { e -> failed = failed + (item.id to (e.message ?: e::class.simpleName.orEmpty())) }
    }
    progress(null, items.size, failed)
}
