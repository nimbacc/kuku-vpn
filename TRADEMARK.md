# Trademark and branding rules

The source code is free (GPL-3.0-or-later). The NAME and ARTWORK are what stay
with this project — the same additional-terms mechanism allowed by GPL section 7.

If you redistribute a modified build, you MUST change:

1. **The display name** — do not ship a fork as "Kuku VPN" / "کوکو وی‌پی‌ان".
2. **The application id** — change `applicationId` in `app/build.gradle.kts`
   (must not start with `app.kukuvpn`).
3. **The launcher icon** — `app/src/main/res/drawable/ic_launcher_foreground.xml`.

You keep every other right the GPL gives you: modify, fork, publish, redistribute.
