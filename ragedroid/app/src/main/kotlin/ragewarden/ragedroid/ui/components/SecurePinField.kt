package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue

@Stable
class SecurePinFieldState {
    internal var buffer: CharArray = CharArray(0)
    internal var lengthState by mutableIntStateOf(0)
    internal var fieldValue by mutableStateOf(TextFieldValue(""))

    val length: Int get() = lengthState

    fun submit(): CharArray = buffer.copyOf(lengthState)

    fun zero() {
        for (i in buffer.indices) buffer[i] = '\u0000'
        buffer = CharArray(0)
        lengthState = 0
        fieldValue = TextFieldValue("")
    }

    internal fun ensureCapacity(min: Int) {
        if (buffer.size >= min) return
        val newSize = if (min < 16) 16 else min
        val grown = CharArray(newSize)
        for (i in 0 until lengthState) grown[i] = buffer[i]
        for (i in buffer.indices) buffer[i] = '\u0000'
        buffer = grown
    }

    internal fun append(ch: Char) {
        ensureCapacity(lengthState + 1)
        buffer[lengthState] = ch
        lengthState += 1
    }

    internal fun trimTo(newLength: Int) {
        if (newLength >= lengthState) return
        for (i in newLength until lengthState) buffer[i] = '\u0000'
        lengthState = newLength
    }
}

@Composable
fun rememberSecurePinFieldState(): SecurePinFieldState =
    remember { SecurePinFieldState() }

@Composable
fun SecurePinField(
    state: SecurePinFieldState,
    modifier: Modifier = Modifier,
    keyboardType: KeyboardType = KeyboardType.NumberPassword,
    singleLine: Boolean = true,
) {
    val masked = "•".repeat(state.length)
    val display = if (state.fieldValue.text == masked) {
        state.fieldValue
    } else {
        TextFieldValue(text = masked, selection = androidx.compose.ui.text.TextRange(masked.length))
    }
    OutlinedTextField(
        value = display,
        onValueChange = { newValue ->
            val newText = newValue.text
            val oldLen = state.length
            val newLen = newText.length
            when {
                newLen > oldLen -> {
                    val added = newLen - oldLen
                    val startIndex = (newText.length - added).coerceAtLeast(0)
                    for (i in 0 until added) {
                        val ch = newText[startIndex + i]
                        if (ch != '•') state.append(ch)
                    }
                }
                newLen < oldLen -> {
                    state.trimTo(newLen)
                }
            }
            state.fieldValue = TextFieldValue(
                text = "•".repeat(state.length),
                selection = androidx.compose.ui.text.TextRange(state.length),
            )
        },
        singleLine = singleLine,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        modifier = modifier,
    )
}
