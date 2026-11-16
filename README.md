# Ghurir

Ghurir is a browser-based web security sandbox with three interactive labs. Run a payload in **Vulnerable** mode, switch to **Fixed**, and replay the same payload.

## Open the project

Open `index.html` in Chrome, Edge, or Firefox. The site uses plain HTML, CSS, and JavaScript. The invoices, redirect destinations, and carts are fictional. Every payload runs in the browser.

## Labs

| Lab | Scenario | OWASP Top 10:2025 | CWE |
|---|---|---|---|
| IDOR | Read an invoice belonging to another user | A01 Broken Access Control | CWE-639 |
| Open Redirect | Send a visitor to an external destination through a trusted link | A01 Broken Access Control | CWE-601 |
| Race Condition | Apply a one-use coupon through concurrent requests | A06 Insecure Design | CWE-362 |

The code displayed in each lab illustrates how the bug and fix can appear in an application. `assets/labs.js` constructs client-side request objects, passes them to separate vulnerable and fixed handlers, and returns structured simulated responses against fresh sample data on every run. These are not real HTTP endpoints, and no server requests are sent. `assets/sandbox.js` handles the mode buttons, payload actions, Reset, and response display.

The Race Condition lab is a deterministic client-side concurrency model, not a reproduction of real database concurrency. A scheduler runs each store call one step at a time, so simultaneous requests interleave predictably. Nothing navigates away from the site in the Open Redirect lab; its response and `Location` value are only reported.

## Test the site

| Check | Vulnerable | Fixed |
|---|---|---|
| IDOR · invoice #102 or #103 | Another user's invoice appears | 403 Forbidden and no invoice details |
| IDOR · own invoice #101 | Invoice appears | Invoice appears |
| IDOR · missing #999 or invalid ID | 404 or 400 response | 404 or 400 response |
| Open Redirect · external URL | 302 to external.example | 400 Bad Request |
| Open Redirect · URL starting with // | 302 to external.example | 400 Bad Request |
| Open Redirect · /account | 302 to portal.example/account | 302 to portal.example/account |
| Open Redirect · malformed URL | 400 Bad Request | 400 Bad Request |
| Race condition · two concurrent requests | 2 discounts and an $80 cart | 1 discount and a $90 cart |
| Race condition · three concurrent requests | 3 discounts and a $70 cart | 1 discount and a $90 cart |
| Race condition · one request | 1 discount and a $90 cart | 1 discount and a $90 cart |

Switch modes before replaying each attack. Check the highlighted lines and source links, and use the navigation on a phone as well as a desktop.

## Publish the team copy

1. Extract the ZIP. In the team's GitHub repository, put `index.html`, the three lab pages, `assets/`, and `README.md` at the top level of `main`.
2. Open **Settings → Pages**. Choose **Deploy from a branch**, select **main** and **/(root)**, and save. [GitHub Pages instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).
3. Open the published URL. Run the checks above on that URL and paste it into the live-site field below.
4. Submit the team's GitHub repository link through the course Discord.

**Live site** · Add the team's GitHub Pages URL here after publication.

## تحضير الفريق للعرض

| المسؤول | الجزء |
|---|---|
| قائد الفريق | يراجع المواضيع مع الـStaff، ينسّق اختبار الرابط المنشور، ويسلّم رابط GitHub |
| صاحب IDOR | يشرح ليش تغيير رقم الفاتورة كشف بيانات مستخدم آخر، وكيف فحص الملكية منعها |
| صاحب Open Redirect | يوضح كيف غيّر معامل next وجهة المتصفح، وكيف سمح الإصلاح بالمسارات الداخلية المحدّدة |
| صاحب Race Condition | يتتبع ترتيب الطلبات في سجل التنفيذ ويشرح ليش الفحص والتحديث الذرّي منع تكرار الخصم |
| مسؤول التصميم | يشرح التنقّل، توحيد صفحات المختبرات، وفحص العرض على الموبايل |

اتفقوا مع الـStaff على المواضيع الثلاث حسب تعليمات المشروع. كل عضو يجرّب أزرار المختبرات الثلاث في الوضعين ويكون قادر يشرح الخلل والإصلاح في كل واحد.

**توزيع الـ15 دقيقة** · دقيقتان مقدمة، 3 دقائق لكل مختبر، دقيقتان للتصميم والاختبار، ودقيقتان للخلاصة. جهّزوا كمان 5 دقائق للأسئلة.

**موعد 42 Amman** · التسليم السبت 21 نوفمبر 2026 قبل 11:59 مساءً بتوقيت عمّان. العرض الأحد 22 نوفمبر 2026.
