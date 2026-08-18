# সিকিউরিটি ফিক্স — Changelog & Deployment গাইড

আগের অডিট রিপোর্টে যা যা পাওয়া গিয়েছিল তার প্রত্যেকটা এখানে ফিক্স করা হয়েছে। কী পাল্টেছে আর কিভাবে ডিপ্লয় করবে — সব নিচে।

## কী কী ফিক্স হয়েছে

| # | সমস্যা | ফিক্স | ফাইল |
|---|---|---|---|
| 1 | Forgeable `admin_auth=true` cookie | D1-এ সংরক্ষিত random session token, `HttpOnly/Secure/SameSite=Strict` cookie | `functions/_lib/security.js`, `functions/api/auth.js`, `functions/api/session.js`, `functions/api/logout.js` |
| 2 | Stored XSS (`innerHTML` + raw title/content) | সব জায়গায় `textContent`/DOM-building + dependency-free allowlist sanitizer | `index.html`, `pages/notice.html`, `auth/admin.html`, `assets/js/sanitize.js` |
| 3 | Plaintext password | PBKDF2 (Web Crypto, 100,000 iterations) hashing | `functions/_lib/security.js`, `functions/api/auth.js` |
| 4 | Brute-force protection নেই | IP-ভিত্তিক rate limit (D1) + optional Turnstile CAPTCHA hook | `functions/_lib/security.js`, `functions/api/auth.js`, `auth/admin.html` |
| 5 | Unrestricted file upload | MIME-type whitelist (pdf/jpg/png/webp), 10MB size limit, পুরোপুরি random filename | `functions/api/upload.js` |
| 6 | Security headers নেই | `_headers` ফাইল (CSP, X-Frame-Options, nosniff, ইত্যাদি) | `_headers` |
| 7 | SRI/unpinned CDN | নোটিশ content রেন্ডার করার জন্য DOMPurify-এর বদলে নিজস্ব dependency-free sanitizer (তাই ওই ঝুঁকি নেই) | `assets/js/sanitize.js` |
| 8 | Input validation নেই | Title/content/URL length ও ফরম্যাট চেক | `functions/api/notices.js` |
| 9 | প্রতি GET-এ DB cleanup | শুধু write অপারেশনে cleanup চলে | `functions/api/notices.js` |
| 11 | `/files/` key validation নেই | Strict regex দিয়ে key validate + nosniff header | `functions/files/[[path]].js` |

## নতুন ফাইল
- `functions/_lib/security.js` — সব security helper (hash, session, rate-limit, headers, housekeeping) এক জায়গায়
- `functions/api/session.js` — লগইন স্ট্যাটাস চেক (client-side cookie-read এর replacement)
- `functions/api/logout.js` — server-side session invalidate
- `assets/js/sanitize.js` — dependency-free HTML sanitizer
- `_headers` — Cloudflare Pages security headers
- `db/migrations/001_security_hardening.sql` — নতুন টেবিল (`sessions`, `login_attempts`)
- `scripts/hash-password.js` — অফলাইন পাসওয়ার্ড হ্যাশ জেনারেটর
- `wrangler.toml.example` — D1/R2 binding ও env var-এর ডকুমেন্টেড রেফারেন্স

## Long-term/lifetime চালানোর জন্য যোগ করা হয়েছে (কেউ বছরে একবারও না ছুঁলেও যেন সমস্যা না হয়)
- **`housekeeping()`** (`functions/_lib/security.js`) — প্রতিবার `/api/auth`-এ হিট হলে expired session ও পুরনো rate-limit window সাফ করে দেয়। এটা না থাকলে `sessions`/`login_attempts` টেবিল সময়ের সাথে অনন্তকাল বড় হতেই থাকতো, কারণ কোথাও কোনো cron/cleanup job ছিল না।
- **env-var ভিত্তিক admin (recommended, simplest)** — `functions/api/auth.js` এখন `env.ADMIN_USERNAME` + `env.ADMIN_PASSWORD` চেক করে। পুরো `users` টেবিল, হ্যাশ জেনারেট করা, কোনোটাই লাগে না।

## ✅ Admin লগইন সেটআপ — সবচেয়ে সহজ পথ (recommended)

Cloudflare Pages dashboard → Settings → Environment variables-এ **"Secret"/Encrypted** টাইপ হিসেবে সরাসরি দুটো ভ্যারিয়েবল বসাও:

- `ADMIN_USERNAME` = `admin` (বা যা চাও)
- `ADMIN_PASSWORD` = তোমার আসল পাসওয়ার্ড (plaintext-ই বসাও, হ্যাশ করার দরকার নেই)

**এটা কেন নিরাপদ:**
- Cloudflare "Secret" env var এনক্রিপ্টেড অবস্থায় স্টোর হয়, সেভ করার পর dashboard-এও value আর কেউ দেখতে পারে না (শুধু re-set/overwrite করা যায়)।
- এটা কোনো ডাটাবেজে (D1) লেখা হচ্ছে না, তাই DB leak হলেও password exposed হবে না।
- সার্ভার-সাইডে (`functions/api/auth.js`) এই ভ্যালুর সাথে তুমি ফর্মে যা টাইপ করো তা **constant-time comparison** দিয়ে মেলানো হয় (timing attack প্রতিরোধ করার জন্য) — সরাসরি `===` দিয়ে না।

**লগইন করার সময়:** অ্যাডমিন প্যানেলের ফর্মে তুমি সবসময় **আসল পাসওয়ার্ডটাই** টাইপ করবে (যা env var-এ বসিয়েছো) — এটাই একমাত্র জিনিস তোমাকে মনে রাখতে হবে। কোনো হ্যাশ generate/copy করার আলাদা ধাপ নেই।

`sessions`/`login_attempts` টেবিল দুটো তবুও D1-তেই লাগবে (এগুলো login session ট্র্যাক করার জন্য, password স্টোর করার জন্য না) — মাইগ্রেশন SQL নিচে দেওয়া আছে।

---

## ⚠️ যদি D1 `users` টেবিলও ব্যবহার করতে চাও (একাধিক admin দরকার হলে)

উপরের env-var পদ্ধতি ব্যবহার করলে **এই সেকশনটা স্কিপ করে যেতে পারো** — শুধু একজন অ্যাডমিন হলে D1 `users` টেবিলের কিছুই লাগে না।

যদি ভবিষ্যতে একাধিক admin অ্যাকাউন্ট লাগে, তখন D1 `users` টেবিলে PBKDF2 হ্যাশ (plaintext না) বসাতে হবে — `generate-admin-hash.html` টুল দিয়ে (ব্রাউজারেই খোলে, Node লাগে না) হ্যাশ বানিয়ে সেটা D1-এ বসাবে:

```sql
UPDATE users SET password = 'pbkdf2$100000$xxxxx$yyyyy' WHERE username = 'admin';
```

D1-এর `users` টেবিলে কখনো plaintext password রেখো না — env var-এর মতো Cloudflare Secret দিয়ে এনক্রিপ্টেড না, D1-এ যা লেখা হয় তা সরাসরি টেবিলেই থাকে।



## R2-তে আগের আপলোড করা ফাইল নিয়ে একটা নোট

`functions/files/[[path]].js` এখন strict filename pattern (`<timestamp>_<32 hex>.<ext>`) ছাড়া কিছু serve করে না। আগের স্কিমে (`Date.now()+'_'+originalname`) আপলোড হওয়া পুরনো ফাইল এই নতুন regex-এ ম্যাচ করবে না, ফলে সেগুলোর লিংক 404 দেখাবে। যদি পুরনো নোটিশে অ্যাটাচ করা কোনো PDF থাকে যেটা রাখা দরকার, সেগুলো নতুন `/api/upload` endpoint দিয়ে re-upload করে নোটিশে নতুন `pdf_url` বসিয়ে দাও।

## ঐচ্ছিক: Turnstile CAPTCHA চালু করা

`auth/admin.html`-এ login form-এ একটা খালি `<div class="cf-turnstile">` রাখা আছে। চালু করতে:
1. Cloudflare Dashboard → Turnstile থেকে একটা site key নাও
2. `<head>`-এ যোগ করো: `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
3. `data-sitekey=""` এর মধ্যে key বসাও
4. Pages প্রজেক্টে `TURNSTILE_SECRET_KEY` environment variable সেট করো

key সেট না করলে সবকিছু আগের মতোই চলবে, শুধু CAPTCHA স্কিপ হয়ে যাবে (`functions/_lib/security.js`-এর `verifyTurnstile()` no-op থাকে)।

## যা ইচ্ছাকৃতভাবে বাদ রাখা হয়েছে (আরও উন্নতির জায়গা, কিন্তু ব্লকার না)

- **CSP-তে `unsafe-inline`**: পুরো কোডবেসে সব পেজেই ভারী inline `<script>`/`onclick=` ব্যবহার হয়েছে। সেগুলো পুরো `addEventListener`-এ রিফ্যাক্টর করে nonce-based strict CSP করা সম্ভব, কিন্তু সেটা এই ফিক্সের স্কোপের বাইরে একটা বড় রিরাইট। এই ফিক্সে যেখানে actual attacker-controlled data render হয় (title/content) সেগুলো `textContent`/sanitizer দিয়ে নিরাপদ করা হয়েছে, যেটাই আসল XSS ভেক্টর ছিল।
- **CDN self-hosting**: Tailwind/Quill/AOS/html2pdf এখনো CDN থেকেই লোড হয়। ঝুঁকি কমাতে চাইলে এগুলো `npm install` করে bundle করে নিজের সার্ভার থেকে সার্ভ করাই সবচেয়ে ভালো — কিন্তু network access ছাড়া আমি এখান থেকে actual package download/SRI hash verify করতে পারিনি, তাই ভুল hash বসিয়ে সাইট ভেঙে দেওয়ার চেয়ে এই ধাপটা তোমার হাতে রাখলাম।
