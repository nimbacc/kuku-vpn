# عیب‌یابی بیلد (اولین بار و تغییر نسخهٔ sing-box)

این راهنما برای وقتیه که بیلد CI یا بیلد لوکال با خطای کامپایل Kotlin در فایل‌های
`bg/KukuVpnService.kt` روبه‌رو می‌شه. علت تقریباً همیشه یکی از این دوتاست:

## ۱. تگ sing-box وجود ندارد یا libbox.aar ساخته نمی‌شود

پیام خطا: `git clone` در job با `ref v1.11.15` شکست می‌خورد یا `gomobile bind` فایل نمی‌سازد.

**راه‌حل:** بالای `.github/workflows/android.yml` مقدار `SINGBOX_VERSION` را به تگ موجودِ
شاخهٔ 1.11.x عوض کنید (لیست تگ‌ها: `https://github.com/SagerNet/sing-box/tags`).
همچنین می‌توانید `GO_VERSION` را به بالاتر ببرید.

## ۲. Kotlin: «member overrides nothing» یا «class is not abstract…»

gomobile برای هر نسخهٔ sing-box یک `libbox.aar` با امضای جاوای مخصوص خودش می‌سازد.
اگر نسخه را تغییر داده‌اید، ممکن است یکی از متدهای زیر اسم/امضای متفاوتی داشته باشد.

**کشف امضای واقعی — یک دستور:**

```bash
unzip -o app/libs/libbox.aar classes.jar -d /tmp/libbox
javap -classpath /tmp/libbox/classes.jar io.nekohasekai.libbox.CommandServerHandler
javap -classpath /tmp/libbox/classes.jar io.nekohasekai.libbox.PlatformInterface
javap -classpath /tmp/libbox/classes.jar io.nekohasekai.libbox.StatusMessage
javap -classpath /tmp/libbox/classes.jar io.nekohasekai.libbox.TunOptions
javap -classpath /tmp/libbox/classes.jar io.nekohasekai.libbox.BoxOptions
```

خروجی `javap` را با پیام خطای Gradle مقایسه کنید و فقط متدهای اعلام‌شده در
`KukuVpnService.kt` را تنظیم کنید. قانون کلی:

- متدی که در پیام خطا می‌گوید «پیاده‌سازی نشده» → از `javap` اسم و امضایش را بردارید و اضافه کنید.
- متدی که می‌گوید «overrides nothing» → حذفش کنید یا امضایش را مطابق `javap` اصلاح کنید.
- گترهای `StatusMessage` معمولاً `in` / `out` / `uptime` / `connectionsIn` / `connectionsOut` هستند؛
  در Kotlin فیلد `in` باید با بک‌تیک نوشته شود: ``message.`in` ``.

## ۳. خطاهای معمول دیگر

| پیام | علت / راه‌حل |
|---|---|
| `establish() returned null` روی گوشی | VPN دیگری فعال است یا Always-on بدون اجازهٔ Kuku؛ اجازهٔ VPN را دوباره بدهید |
| `core listener did not open within 15s` | پورت 2080 اشغال است یا هسته با کانفیگ بوت نشد؛ لاگ تب «گزارش» دلیل دقیق را دارد |
| `no profile found` در import | لینک پشتیبانی نمی‌شود؛ اسکیم‌های مجاز در README آمده است |
| بیلد اندروید: `libbox.aar not found` | artifact `libbox` نیامده؛ اول job اول سبز شود، سپس job دوم را دوباره اجرا کنید |
| Release unsigned | Secretهای امضا تنظیم نشده‌اند؛ راهنمای README بخش «کلید امضا» |

## ۴. ارتقا به sing-box 1.12+ (نقشهٔ راه)

AnyTLS و چند قابلیت دیگر در 1.12 به بعد هستند. برای ارتقا:

1. `SINGBOX_VERSION` را به تگ 1.12 یا بالاتر بگذارید.
2. امضاهای `CommandServer` و `PlatformInterface` با `javap` مقایسه و در
   `KukuVpnService.kt` به‌روزرسانی کنید (در 1.14 متدهای neighbour/bridge/tailscale
   به `PlatformInterface` اضافه شده‌اند و باید بدنهٔ خالی برایشان بنویسید).
3. اسکیمای کانفیگ: در 1.12 نام فیلدهای tun از `inet4_address` به `address` تغییر
   کرده — در `SingBoxConfigBuilder.kt` اصلاح کنید.
