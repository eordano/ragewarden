package ragewarden.ragedroid.journey;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A third-party login form for the delivery flows. It runs in the test APK's own
 * process, so it is a foreign app to Ragewarden's autofill service and keyboard.
 * Sign-in prints the username and a digest of the password, which is how the
 * test reads back a password field that accessibility masks.
 *
 * Java, not Kotlin: the test APK leaves the Kotlin runtime to the app APK, and
 * this process never loads the app's classes, so a Kotlin call here died with
 * "NoClassDefFoundError: kotlin/jvm/internal/Intrinsics" on the first sign-in.
 */
public final class LoginFixtureActivity extends Activity {
    public static final String USERNAME = "fixture-username";
    public static final String PASSWORD = "fixture-password";
    public static final String RESULT = "fixture-result";
    public static final String SUBMIT = "Fixture sign in";

    /** Extra and view: the launch's id, so the test knows it is talking to this instance. */
    public static final String RUN = "fixture-run";

    /**
     * Extra: the fields do not raise the soft keyboard. With no keyboard asking
     * for inline suggestions, Android shows autofill datasets in its own
     * dropdown, rather than as chips the keyboard may or may not display.
     */
    public static final String NO_KEYBOARD = "fixture-no-keyboard";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EditText user = new EditText(this);
        user.setHint("Fixture username");
        user.setContentDescription(USERNAME);
        user.setInputType(InputType.TYPE_CLASS_TEXT);
        user.setAutofillHints(View.AUTOFILL_HINT_USERNAME);

        EditText pass = new EditText(this);
        pass.setHint("Fixture password");
        pass.setContentDescription(PASSWORD);
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pass.setAutofillHints(View.AUTOFILL_HINT_PASSWORD);

        TextView result = new TextView(this);
        result.setContentDescription(RESULT);

        if (getIntent().getBooleanExtra(NO_KEYBOARD, false)) {
            user.setShowSoftInputOnFocus(false);
            pass.setShowSoftInputOnFocus(false);
        }

        String run = getIntent().getStringExtra(RUN);
        TextView runView = new TextView(this);
        runView.setContentDescription(RUN);
        runView.setText(run == null ? "" : run);

        Button submit = new Button(this);
        // Material buttons are all-caps, and accessibility reports the
        // transformed text, so By.text(SUBMIT) would never match.
        submit.setAllCaps(false);
        submit.setText(SUBMIT);
        submit.setOnClickListener(v -> result.setText(summary(user.getText().toString(), pass.getText().toString())));

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 160, 48, 48);
        layout.addView(user);
        layout.addView(pass);
        layout.addView(submit);
        layout.addView(result);
        layout.addView(runView);
        setContentView(layout);
    }

    public static String summary(String user, String password) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        StringBuilder out = new StringBuilder("user=").append(user).append(" pw=");
        for (int i = 0; i < 8; i++) out.append(String.format("%02x", digest[i]));
        return out.toString();
    }
}
