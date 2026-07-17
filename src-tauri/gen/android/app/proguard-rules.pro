# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# --- Yellow VPN JNI / Tauri bridge (release-only crash fix) ---
# The Rust engine reaches into these Kotlin symbols BY NAME across the JNI
# boundary, and Tauri loads the plugin reflectively:
#   * VpnBridge.runEngine / stopEngine  -> native exports
#     (Java_app_yellowvpn_plugin_VpnBridge_runEngine / _stopEngine); R8 renaming
#     the class or the methods breaks the symbol lookup -> UnsatisfiedLinkError.
#   * StateCallback.onState             -> resolved via JNI GetMethodID("onState").
#   * TunBuilder.configure              -> resolved via JNI call_method("configure").
#   * VpnPlugin (@TauriPlugin) + its @Command methods -> instantiated/invoked by
#     the Tauri plugin manager via reflection.
# None of these are covered by the com.ff15.yellow_vpn.* rules, so a minified
# release build renamed them and the engine failed to start on every real device
# — an infinite connect loop — while debug builds (minify off) worked. Keep the
# whole plugin package verbatim.
-keep class app.yellowvpn.plugin.** { *; }
-keepclassmembers class app.yellowvpn.plugin.** { *; }
# Keep native method bindings regardless of which package declares them.
-keepclasseswithmembernames class * {
    native <methods>;
}