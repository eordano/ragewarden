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
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    fun loadCandidates() {
        val all = repo.snapshot()
        val items = all.filter { !it.rage }
        val staleRage = if (rotationTracker.isStale(repo.accountId)) {
            all.count { it.rage }
        } else {
            0
        }
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
                    val pt = repo.decrypt(item.id, emptyList()).getOrThrow()
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

    fun markRotationFresh() {
        rotationTracker.markFresh(repo.accountId)
        _state.update { it.copy(staleRageItemCount = 0) }
    }
}
