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
    const id = Number(req.resourceId);
    steps.push("Read invoice ID from the request.");
    if (!Number.isInteger(id)) return makeResponse(400, { error: "Invalid invoice ID." });
    const invoice = await invoices.findById(id);
    if (!invoice) return makeResponse(404, { error: "Invoice not found." });
    steps.push("Return the invoice without checking its owner.");
    return makeResponse(200, invoice);
  }

  async function viewInvoiceFixed(req, invoices, steps) {
    const id = Number(req.resourceId);
    steps.push("Read invoice ID from the request.");
    if (!Number.isInteger(id)) return makeResponse(400, { error: "Invalid invoice ID." });
    const invoice = await invoices.findById(id);
    if (!invoice) return makeResponse(404, { error: "Invoice not found." });
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

  const invoiceCodeSamples = {
    vulnerable: viewInvoiceVulnerable.toString(),
    fixed: viewInvoiceFixed.toString(),
  };

  // ---------------------------------------------------------------------------
  // Lab 2 · Open Redirect (CWE-601)
  // ---------------------------------------------------------------------------
  const redirectOrigin = "https://portal.example";

  function parseRedirectDestination(value) {
    try {
      const destination = new URL(value, redirectOrigin);
      if (destination.protocol !== "http:" && destination.protocol !== "https:") return null;
      return destination;
    } catch {
      return null;
    }
  }

  function continueToVulnerable(req) {
    const next = req.query.next;
    const destination = parseRedirectDestination(next);
    if (!destination) {
      return makeResponse(400, { error: "Invalid redirect destination." }, { "Cache-Control": "no-store" });
    }
    return makeResponse(302, { message: "Redirect decision recorded; no navigation occurred." }, {
      "Cache-Control": "no-store",
      Location: next,
    });
  }

  const allowedDestinations = new Set(["/account", "/help"]);
  function continueToFixed(req) {
    const next = req.query.next;
    if (!allowedDestinations.has(next)) {
      return makeResponse(400, { error: "Destination is not in the internal-route allowlist." }, {
        "Cache-Control": "no-store",
      });
    }
    return makeResponse(302, { message: "Allowed internal redirect; no navigation occurred." }, {
      "Cache-Control": "no-store",
      Location: next,
    });
  }

  const redirectCodeSamples = {
    vulnerable: continueToVulnerable.toString(),
    fixed: continueToFixed.toString(),
  };

  function simulateRedirect(mode, payload) {
    const next = String(payload);
    const queryString = new URLSearchParams({ next }).toString();
    const request = makeRequest({ method: "GET", path: "/continue", query: { next } });
    const handler = mode === "fixed" ? continueToFixed : continueToVulnerable;
    const response = handler(request);
    const location = response.headers.Location;
    const destination = location ? parseRedirectDestination(location) : null;
    const external = Boolean(destination && destination.origin !== redirectOrigin);

    return {
      request,
      requestLine: "/continue?" + queryString,
      response,
      events: response.status === 400
        ? ["Read the next query parameter.", "Reject destination."]
        : ["Read the next query parameter.", "Return simulated Location: " + location + "; no navigation occurs."],
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
        getCart(cartId) {
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
        addDiscount(cartId, amount) {
          return io(request, "addDiscount(" + amount + ")", () => {
            const before = cart.discount;
            cart.discount += amount;
            return {
              value: true,
              text: "discount " + dollars(before) + " → " + dollars(cart.discount),
            };
          });
        },
        markCouponUsed(cartId) {
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
        claimCouponAndDiscount(cartId, amount) {
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

  function createCouponHandlers(store) {
    async function isValidCoupon(code) {
      const coupon = await store.findCoupon(code);
      return Boolean(coupon && coupon.valid);
    }

    const vulnerable = async function applyCoupon(cartId, code) {
      const cart = await store.getCart(cartId);
      if (cart.couponUsed) {
        return { applied: false, status: 409 };
      }
      if (!(await isValidCoupon(code))) {
        return { applied: false, status: 400 };
      }
      await store.addDiscount(cartId, discount);
      await store.markCouponUsed(cartId);
      return { applied: true, status: 200, discount };
    };

    const fixed = async function applyCoupon(cartId, code) {
      if (!(await isValidCoupon(code))) {
        return { applied: false, status: 400 };
      }
      const claimed = await store.claimCouponAndDiscount(cartId, discount);
      if (!claimed) {
        return { applied: false, status: 409 };
      }
      return { applied: true, status: 200, discount };
    };

    return { vulnerable, fixed };
  }

  const raceConditionCodeSamples = (() => {
    const handlers = createCouponHandlers(null);
    return {
      vulnerable: handlers.vulnerable.toString(),
      fixed: handlers.fixed.toString(),
    };
  })();

  const couponAttempts = { normal: 1, pair: 2, triple: 3 };

  async function redeemCoupon(mode, payload) {
    const count = couponAttempts[payload];
    const store = createCouponStore();

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
      const handlers = createCouponHandlers(store.forRequest(name));
      const handler = mode === "fixed" ? handlers.fixed : handlers.vulnerable;
      return handler("cart-1", request.body.code).then((outcome) => {
        const error = outcome.status === 409
          ? "Coupon has already been used."
          : outcome.status === 400
            ? "Invalid coupon."
            : undefined;
        const body = outcome.applied
          ? { applied: true, discount: dollars(outcome.discount) }
          : { applied: false, error };
        const result = makeResponse(outcome.status, body);
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
    codeSamples: {
      idor: invoiceCodeSamples,
      "open-redirect": redirectCodeSamples,
      "race-condition": raceConditionCodeSamples,
    },
  };
})();
