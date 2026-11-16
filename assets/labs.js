const securityLabs = (() => {
  function makeRequest({ method, path, query = {}, session = null, body = null, ...context }) {
    return { method, path, query, session, body, ...context };
  }

  function makeResponse(status, body, headers = {}) {
    return { status, headers: { "Content-Type": "application/json", ...headers }, body };
  }

  function statusLabel(status) {
    return ({ 200: "OK", 302: "Found", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict" })[status] || "Response";
  }

  function dollars(value) {
    return "$" + value.toFixed(2);
  }

  // ---------------------------------------------------------------------------
  // Lab 1 · IDOR (CWE-639)
  // ---------------------------------------------------------------------------
  const viewerId = "U-01";

  // A fresh copy of the sample data is built for every run.
  function createInvoiceStore() {
    const rows = [
      { id: 101, ownerId: "U-01", customer: "Lina Haddad", item: "Desk lamp", total: 24 },
      { id: 102, ownerId: "U-02", customer: "Omar Nasser", item: "Cable tray", total: 18 },
      { id: 103, ownerId: "U-03", customer: "Sara Khalil", item: "Monitor stand", total: 42 },
    ];
    return {
      async findById(id) {
        const row = rows.find((record) => record.id === id);
        return row ? { ...row } : null;
      },
    };
  }

  async function viewInvoiceVulnerable(req, invoices, steps) {
    steps.push("Read invoice ID from request path.");
    const match = /^\/invoices\/([^/]+)$/.exec(req.path);
    const idText = match && match[1];
    if (!idText || !/^\d+$/.test(idText)) {
      steps.push("Reject ID: it is not an integer.");
      return makeResponse(400, { error: "Invoice ID must be an integer." });
    }
    steps.push("Look up invoice #" + idText + " in the sample store.");
    const invoice = await invoices.findById(Number(idText));
    if (!invoice) {
      steps.push("No matching invoice exists.");
      return makeResponse(404, { error: "Invoice not found." });
    }
    steps.push("Return the invoice without checking its owner.");
    // Vulnerable: returns any matching invoice without checking its owner.
    return makeResponse(200, invoice);
  }

  async function viewInvoiceFixed(req, invoices, steps) {
    steps.push("Read invoice ID from request path.");
    const match = /^\/invoices\/([^/]+)$/.exec(req.path);
    const idText = match && match[1];
    if (!idText || !/^\d+$/.test(idText)) {
      steps.push("Reject ID: it is not an integer.");
      return makeResponse(400, { error: "Invoice ID must be an integer." });
    }
    steps.push("Look up invoice #" + idText + " in the sample store.");
    const invoice = await invoices.findById(Number(idText));
    if (!invoice) {
      steps.push("No matching invoice exists.");
      return makeResponse(404, { error: "Invoice not found." });
    }
    steps.push("Compare invoice owner with authenticated viewer " + req.session.userId + ".");
    // Fixed: an authenticated viewer can read only invoices they own.
    if (invoice.ownerId !== req.session.userId) {
      steps.push("Reject request: invoice belongs to " + invoice.ownerId + ".");
      return makeResponse(403, { error: "Forbidden: invoice belongs to another user." });
    }
    steps.push("Owner matches; return the invoice.");
    return makeResponse(200, invoice);
  }

  async function viewInvoice(mode, payload) {
    const resourceId = String(payload);
    const request = makeRequest({
      method: "GET",
      path: "/invoices/" + resourceId,
      session: { userId: viewerId },
      resourceId,
    });
    const handler = mode === "fixed" ? viewInvoiceFixed : viewInvoiceVulnerable;
    const steps = [];
    const response = await handler(request, createInvoiceStore(), steps);
    const invoice = response.status === 200 ? response.body : null;
    const ownInvoice = Boolean(invoice && invoice.ownerId === request.session.userId);
    const exposed = Boolean(invoice && !ownInvoice);

    return {
      request,
      response,
      events: steps,
      tone: exposed ? "exposed" : response.status === 403 ? "blocked" : ownInvoice ? "allowed" : "neutral",
      status: response.status + " " + statusLabel(response.status),
      title: response.status === 200 ? "Invoice #" + invoice.id + " returned" : statusLabel(response.status),
      detail: exposed
        ? "The response contains an invoice owned by another user because this handler skipped the ownership check."
        : response.status === 403
          ? "The ownership check rejected the request; no invoice data was returned."
          : ownInvoice
            ? "The response contains the authenticated viewer's own invoice."
            : response.status === 404
              ? "No invoice exists with this resource ID."
              : "The path contains an invalid invoice ID.",
    };
  }

  // ---------------------------------------------------------------------------
  // Lab 2 · Open Redirect (CWE-601)
  // ---------------------------------------------------------------------------
  const redirectOrigin = "https://portal.example";

  function parseRedirectDestination(value) {
    if (typeof value !== "string" || /[\u0000-\u0020\u007f\\]/.test(value)) return null;
    try {
      const destination = new URL(value, redirectOrigin);
      if (destination.protocol !== "http:" && destination.protocol !== "https:") return null;
      return destination;
    } catch {
      return null;
    }
  }

  function continueToVulnerable(req) {
    const steps = ["Read the next query parameter."];
    const next = req.query.next;
    if (!parseRedirectDestination(next)) {
      steps.push("Reject destination: it is not a valid HTTP or HTTPS URL.");
      return { response: makeResponse(400, { error: "Invalid redirect destination." }, { "Cache-Control": "no-store" }), steps };
    }
    steps.push("Parse destination as " + parseRedirectDestination(next).href + ".");
    steps.push("No allowlist check; set Location to the supplied destination.");
    // Vulnerable: valid external destinations are accepted without an allowlist.
    return { response: makeResponse(302, { message: "Redirect decision recorded; no navigation occurred." }, {
      "Cache-Control": "no-store",
      Location: next,
    }), steps };
  }

  const allowedDestinations = new Set(["/account", "/help"]);
  function continueToFixed(req) {
    const steps = ["Read the next query parameter."];
    const next = req.query.next;
    if (!allowedDestinations.has(next)) {
      steps.push("Compare destination with the exact internal-route allowlist.");
      steps.push("Reject destination: no exact route matched.");
      return { response: makeResponse(400, {
        error: "Destination is not in the internal-route allowlist.",
        allowedDestinations: [...allowedDestinations],
      }, { "Cache-Control": "no-store" }), steps };
    }
    steps.push("Exact allowlist match; set Location to the approved internal route.");
    return { response: makeResponse(302, { message: "Allowed internal redirect; no navigation occurred." }, {
      "Cache-Control": "no-store",
      Location: next,
    }), steps };
  }

  function simulateRedirect(mode, payload) {
    const next = String(payload);
    const queryString = new URLSearchParams({ next }).toString();
    const request = makeRequest({ method: "GET", path: "/continue", query: { next } });
    const handler = mode === "fixed" ? continueToFixed : continueToVulnerable;
    const execution = handler(request);
    const response = execution.response;
    const location = response.headers.Location;
    const destination = location ? parseRedirectDestination(location) : null;
    const external = Boolean(destination && destination.origin !== redirectOrigin);

    return {
      request,
      requestLine: "GET /continue?" + queryString,
      response,
      events: execution.steps,
      tone: external ? "exposed" : response.status === 400 ? "blocked" : "allowed",
      status: external ? "External redirect" : response.status === 302 ? "Internal redirect" : "Redirect blocked",
      title: external ? "External redirect returned" : response.status === 302 ? "Internal redirect returned" : "Redirect rejected",
      detail: external
        ? "The Location header points outside portal.example. The lab reports it without navigating."
        : response.status === 302
          ? "The Location header names an explicitly allowed internal route; the lab does not navigate."
          : response.body.error + " The browser would remain on the lab page.",
    };
  }

  // ---------------------------------------------------------------------------
  // Lab 3 · Race Condition (CWE-362)
  //
  // Browser-based concurrency simulation. A browser tab cannot reproduce real
  // database concurrency, so every store call goes through a deterministic
  // scheduler. Each call is queued, and the scheduler runs queued calls one at
  // a time, oldest first. Requests that start together therefore interleave
  // step by step: every request finishes step N before any request starts N+1.
  // ---------------------------------------------------------------------------
  const startingTotal = 100;
  const discount = 10;
  const couponCode = "LAB10";

  function createCouponStore() {
    const cart = { id: "cart-1", subtotal: startingTotal, discount: 0, couponUsed: false };
    const coupons = { [couponCode]: { valid: true } };
    const queue = [];
    const log = [];
    let step = 0;

    function note(request, text) {
      log.push(request + " · " + text);
    }

    // Queue one store call. Each state operation runs as one scheduler step.
    function io(request, name, work) {
      return new Promise((resolve) => queue.push({ request, name, work, resolve }));
    }

    async function run() {
      while (queue.length > 0) {
        const op = queue.shift();
        step += 1;
        const outcome = op.work();
        log.push("Step " + step + " · " + op.request + " · " + op.name + " → " + outcome.text);
        op.resolve(outcome.value);
        // Let the request that just resumed queue its next call before the
        // scheduler picks the next one.
        await new Promise((done) => setTimeout(done, 0));
      }
    }

    function forRequest(request) {
      return {
        note(text) {
          note(request, text);
        },
        getCart() {
          return io(request, "getCart()", () => ({
            value: { ...cart },
            text: "read couponUsed=" + cart.couponUsed + ", discount " + dollars(cart.discount),
          }));
        },
        findCoupon(code) {
          return io(request, "findCoupon()", () => ({
            value: coupons[code] ? { ...coupons[code] } : null,
            text: "coupon " + code + " is valid",
          }));
        },
        addDiscount(amount) {
          return io(request, "addDiscount(" + amount + ")", () => {
            const before = cart.discount;
            cart.discount += amount;
            return {
              value: true,
              text: "discount " + dollars(before) + " → " + dollars(cart.discount),
            };
          });
        },
        markCouponUsed() {
          return io(request, "markCouponUsed()", () => {
            const before = cart.couponUsed;
            cart.couponUsed = true;
            return { value: true, text: "couponUsed " + before + " → true" };
          });
        },
        // One conditional update. The check and the write happen inside the
        // same scheduler step, like
        //   UPDATE carts SET coupon_used = true, discount = discount + 10
        //   WHERE id = ? AND coupon_used = false
        // so no other request can run between them.
        claimCouponAndDiscount(amount) {
          return io(request, "claimCouponAndDiscount(" + amount + ")", () => {
            if (cart.couponUsed) {
              return { value: false, text: "0 rows matched (couponUsed is already true), nothing changed" };
            }
            cart.couponUsed = true;
            const before = cart.discount;
            cart.discount += amount;
            return {
              value: true,
              text: "1 row matched: couponUsed false → true, discount " + dollars(before) + " → " + dollars(cart.discount),
            };
          });
        },
      };
    }

    return { cart, log, run, forRequest };
  }

  async function assertCouponIsValid(store, code) {
    const coupon = await store.findCoupon(code);
    if (!coupon || !coupon.valid) throw new Error("Invalid coupon");
  }

  // Vulnerable: checking coupon state and updating it are separate operations.
  async function applyCouponVulnerable(store, request) {
    const cart = await store.getCart();
    store.note("state check: couponUsed=" + cart.couponUsed);
    if (cart.couponUsed) {
      return makeResponse(409, { applied: false, error: "Coupon has already been used." });
    }
    try {
      await assertCouponIsValid(store, request.body.code);
    } catch {
      return makeResponse(400, { applied: false, error: "Invalid coupon." });
    }
    await store.addDiscount(discount);
    await store.markCouponUsed();
    return makeResponse(200, { applied: true, discount: dollars(discount) });
  }

  // Fixed: the coupon check and claim happen inside one atomic store operation.
  async function applyCouponFixed(store, request) {
    try {
      await assertCouponIsValid(store, request.body.code);
    } catch {
      return makeResponse(400, { applied: false, error: "Invalid coupon." });
    }
    const claimed = await store.claimCouponAndDiscount(discount);
    if (!claimed) return makeResponse(409, { applied: false, error: "Coupon has already been used." });
    return makeResponse(200, { applied: true, discount: dollars(discount) });
  }

  const couponAttempts = { normal: 1, pair: 2, triple: 3 };

  async function redeemCoupon(mode, payload) {
    const count = couponAttempts[payload];
    const store = createCouponStore();
    const applyCoupon = mode === "fixed" ? applyCouponFixed : applyCouponVulnerable;

    // Start every request before the scheduler runs anything, so they are
    // genuinely in flight at the same time.
    const requests = Array.from({ length: count }, (_, index) => {
      const name = "Request " + String.fromCharCode(65 + index);
      const request = makeRequest({
        method: "POST",
        path: "/cart/coupon",
        session: { userId: viewerId },
        body: { code: couponCode },
        requestId: name,
      });
      store.log.push(name + " · request created for POST /cart/coupon");
      return applyCoupon(store.forRequest(name), request).then((result) => {
        store.log.push(name + " · response " + result.status + " " + statusLabel(result.status));
        return { request, response: result };
      });
    });
    await store.run();
    const results = await Promise.all(requests);

    const applied = results.filter((result) => result.response.body.applied).length;
    const duplicate = applied > 1;
    const rejected = count - applied;
    const cartTotal = store.cart.subtotal - store.cart.discount;

    const response = makeResponse(200, {
      requests: results.map(({ request, response: itemResponse }) => ({
        requestId: request.requestId,
        status: itemResponse.status,
        body: itemResponse.body,
      })),
      initialCartTotal: dollars(startingTotal),
      finalCartTotal: dollars(cartTotal),
      totalDiscount: dollars(store.cart.discount),
      succeeded: applied,
      rejected,
      couponUsed: store.cart.couponUsed,
    });

    return {
      request: {
        method: "POST",
        path: "/cart/coupon",
        query: {},
        session: { userId: viewerId },
        body: { code: couponCode },
        concurrentRequests: count,
        model: "Deterministic client-side concurrency model; not real database concurrency.",
      },
      response,
      tone: duplicate ? "exposed" : rejected > 0 ? "blocked" : "allowed",
      status: duplicate ? "Coupon reused" : rejected > 0 ? "Extra attempts blocked" : "Coupon applied",
      title: applied + (applied === 1 ? " discount applied" : " discounts applied"),
      detail: duplicate
        ? "Several requests read the coupon as unused before any request recorded it as used."
        : rejected > 0
          ? "Only one request claimed the coupon. The conditional update matched no rows for the others."
          : "The one-use coupon was applied exactly once.",
      events: store.log,
    };
  }

  return {
    idor: viewInvoice,
    "open-redirect": simulateRedirect,
    "race-condition": redeemCoupon,
  };
})();
