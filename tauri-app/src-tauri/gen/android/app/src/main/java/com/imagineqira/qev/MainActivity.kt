package com.imagineqira.qev

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
    }

    /**
     * Handle VIEW / SEND intents that carry a .vault.json file.
     *
     * When a user taps a .vault.json file in their file manager or
     * email, Android routes to QEV's MainActivity via the intent
     * filter in AndroidManifest.xml. We read the file's content
     * via ContentResolver (scoped storage) and inject it into the
     * WebView's decrypt textarea via JavaScript.
     *
     * The JS injection is simple: set the textarea's value and
     * switch to the "Open a vault" tab. The user still needs to
     * enter the phrase — we never auto-decrypt.
     */
    private fun handleIncomingIntent(intent: Intent?) {
        if (intent == null) return

        val uri: Uri? = when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> intent.getParcelableExtra(Intent.EXTRA_STREAM)
            else -> null
        }

        if (uri == null) return

        try {
            val text = contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
            if (text.isNullOrBlank()) return

            // Escape the vault JSON for embedding in a JS string.
            // Replace backslashes first, then quotes, then newlines.
            val escaped = text
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "")

            // Inject into the WebView after a short delay to let
            // the page finish loading (on cold launch the WebView
            // may not be ready yet).
            val webView = this.getWebView()
            webView?.postDelayed({
                webView.evaluateJavascript(
                    """
                    (function() {
                        var ta = document.getElementById('vault-decrypt-input');
                        if (ta) {
                            ta.value = "$escaped";
                            var tab = document.querySelector('[data-app-tab="open"]');
                            if (tab) tab.click();
                        }
                    })();
                    """.trimIndent(),
                    null
                )
            }, 500)
        } catch (e: Exception) {
            // Silently ignore read failures — the user can still
            // paste manually. Log for debugging if needed.
            android.util.Log.w("QEV", "Failed to read intent URI: ${e.message}")
        }
    }

    /**
     * Get the WebView from the Tauri activity. TauriActivity exposes
     * it via getWebView() or through the window's content view
     * hierarchy. This is a best-effort accessor — if the hierarchy
     * changes in a future Tauri version, the intent handler degrades
     * to a no-op and the user can still paste manually.
     */
    private fun getWebView(): android.webkit.WebView? {
        return try {
            // TauriActivity stores the WebView as a tagged view
            // in the content hierarchy. Walk the view tree.
            val root = window.decorView
            findWebView(root)
        } catch (e: Exception) {
            null
        }
    }

    private fun findWebView(view: android.view.View): android.webkit.WebView? {
        if (view is android.webkit.WebView) return view
        if (view is android.view.ViewGroup) {
            for (i in 0 until view.childCount) {
                val found = findWebView(view.getChildAt(i))
                if (found != null) return found
            }
        }
        return null
    }
}
