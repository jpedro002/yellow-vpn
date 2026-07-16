# THIS FILE IS AUTO-GENERATED. DO NOT MODIFY!!

# Copyright 2020-2023 Tauri Programme within The Commons Conservancy
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: MIT

-keep class com.ff15.yellow_vpn.* {
  native <methods>;
}

-keep class com.ff15.yellow_vpn.WryActivity {
  public <init>(...);

  void setWebView(com.ff15.yellow_vpn.RustWebView);
  java.lang.Class getAppClass(...);
  int getId();
  java.lang.String getVersion();
  int startActivity(...);
}

-keep class com.ff15.yellow_vpn.Ipc {
  public <init>(...);

  @android.webkit.JavascriptInterface public <methods>;
}

-keep class com.ff15.yellow_vpn.RustWebView {
  public <init>(...);

  void loadUrlMainThread(...);
  void loadHTMLMainThread(...);
  void evalScript(...);
}

-keep class com.ff15.yellow_vpn.RustWebChromeClient,com.ff15.yellow_vpn.RustWebViewClient {
  public <init>(...);
}
