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

The vulnerable and fixed code displayed in each lab is generated from the same handler functions that the payload buttons execute in `assets/labs.js`; the examples are not separately maintained copies. `assets/sandbox.js` renders the function source as text and handles mode buttons, payload actions, Reset, and response display. Each run uses fresh fictional in-memory data. These are not real HTTP endpoints, and no server requests are sent.

All demos are safe, browser-only simulations. They use fictional sample data, make no backend or other network requests, execute no malicious code, and never navigate to an external destination. The Open Redirect lab reports the simulated `Location` value only. The Race Condition lab is a deterministic client-side concurrency model, not a reproduction of real database concurrency: a scheduler runs each store call one step at a time so simultaneous requests interleave predictably.

## Test the site

| Check | Vulnerable | Fixed |
|---|---|---|
| IDOR · invoice #102 or #103 | Another user's invoice appears | 403 Forbidden and no invoice details |
| IDOR · own invoice #101 | Invoice appears | Invoice appears |
| Open Redirect · `https://hacker.com/login` | 302 with external Location reported; no navigation | 400 Bad Request |
| Open Redirect · `https://intra.42.fr@hacker.com/login` | 302 with external Location reported; no navigation | 400 Bad Request |
| Open Redirect · /account | 302 with Location: /account (hypothetical internal route) | 302 with Location: /account (hypothetical internal route) |
| Race condition · two concurrent requests | 2 discounts and an $80 cart | 1 discount and a $90 cart |
| Race condition · three concurrent requests | 3 discounts and a $70 cart | 1 discount and a $90 cart |
| Race condition · one request | 1 discount and a $90 cart | 1 discount and a $90 cart |

Switch modes before replaying each attack. The IDOR attacks are invoice #102 and #103; both reveal another user's fictional invoice in Vulnerable mode and return 403 in Fixed mode. `GET /invoices/101` remains allowed in both modes. The two redirect attacks return external destinations in Vulnerable mode and are rejected in Fixed mode; `/account` remains an allowed internal destination in both modes. Race attacks (two or three concurrent requests) apply duplicate discounts in Vulnerable mode and only one discount in Fixed mode; applying `LAB10` once succeeds in both modes. Check the highlighted lines and source links, and use the navigation on a phone as well as a desktop.

## Publish the team copy

1. Put `index.html`, the three lab pages, `assets/`, and `README.md` at the top level of the team's GitHub repository.
2. Open **Settings → Pages**. Choose **Deploy from a branch**, select **main** and **/(root)**, and save. See [GitHub Pages instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).
3. After deployment, open the published page and run the checks above on that URL. Add the URL below only after confirming it works.
4. Submit the team's GitHub repository link through the course Discord.

**Live site** · `[Team: fill in the verified live URL after publication]`

