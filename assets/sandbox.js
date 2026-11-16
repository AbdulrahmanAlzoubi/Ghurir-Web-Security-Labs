const sandbox = document.querySelector("[data-sandbox]");
const modeButtons = [...sandbox.querySelectorAll("[data-mode-button]")];
const payloadButtons = [...sandbox.querySelectorAll("[data-payload]")];
const response = sandbox.querySelector("[data-response]");
const request = sandbox.querySelector("[data-request]");
const requestLabel = sandbox.querySelector("[data-request-label]");
const requestText = sandbox.querySelector("[data-request-text]");
const statusBadge = sandbox.querySelector("[data-status]");
const resultTitle = sandbox.querySelector("[data-result-title]");
const resultDetail = sandbox.querySelector("[data-result-detail]");
const resultData = sandbox.querySelector("[data-result-data]");
const runScenario = securityLabs[sandbox.dataset.sandbox];

let mode = "vulnerable";
let currentRun = 0;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function renderFacts(facts) {
  const list = element("dl", undefined, "facts");
  for (const [label, value] of facts) {
    const item = element("div");
    item.append(element("dt", label), element("dd", value));
    list.append(item);
  }
  return list;
}

function renderEvents(events) {
  const timeline = element("div", undefined, "event-log");
  const list = element("ol");
  for (const event of events) list.append(element("li", event));
  timeline.append(element("h4", "Execution order"), list);
  return timeline;
}

function renderExchange(result) {
  const exchange = element("section", undefined, "response-exchange");
  const responseView = result.response;
  const responsePanel = element("div", undefined, "exchange-block");
  responsePanel.append(element("h4", "Simulated response · " + responseView.status + " " + statusLabel(responseView.status)));
  const headersPre = element("pre");
  headersPre.append(element("code", "Headers\n" + JSON.stringify(responseView.headers, null, 2)));
  const bodyPre = element("pre");
  bodyPre.append(element("code", "Body\n" + JSON.stringify(responseView.body, null, 2)));
  responsePanel.append(headersPre, bodyPre);
  exchange.append(responsePanel);
  return exchange;
}

function statusLabel(status) {
  return ({ 200: "OK", 302: "Found", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict" })[status] || "Response";
}

function showStatus(tone, status, title, detail) {
  statusBadge.dataset.tone = tone;
  statusBadge.textContent = status;
  resultTitle.textContent = title;
  resultDetail.textContent = detail;
}

function resetResponse() {
  response.setAttribute("aria-busy", "false");
  request.hidden = true;
  resultData.replaceChildren();
  showStatus("neutral", "Ready", "Run a payload", "The request and its outcome will appear here.");
  for (const button of payloadButtons) button.dataset.selected = "false";
}

for (const button of modeButtons) {
  button.addEventListener("click", () => {
    if (mode === button.dataset.modeButton) return;
    mode = button.dataset.modeButton;
    currentRun += 1;
    sandbox.dataset.mode = mode;
    for (const option of modeButtons) {
      option.setAttribute("aria-pressed", String(option === button));
    }
    resetResponse();
  });
}

const resetButton = sandbox.querySelector("[data-reset]");
if (resetButton) {
  resetButton.addEventListener("click", () => {
    currentRun += 1;
    resetResponse();
  });
}

for (const button of payloadButtons) {
  button.addEventListener("click", async () => {
    const run = ++currentRun;
    for (const option of payloadButtons) option.dataset.selected = String(option === button);

    response.setAttribute("aria-busy", "true");
    resultData.replaceChildren();
    request.hidden = true;
    showStatus("neutral", "Running", "Running the simulation", "Waiting for the result.");

    try {
      const result = await runScenario(mode, button.dataset.payload);
      if (run !== currentRun) return;

      const query = new URLSearchParams(result.request.query || {}).toString();
      const requestTarget = result.requestLine || result.request.path + (query ? "?" + query : "");
      const requestLines = [result.request.method + " " + requestTarget];
      if (result.request.resourceId) requestLines.push("Resource ID: " + result.request.resourceId);
      if (result.request.session) requestLines.push("Session: " + JSON.stringify(result.request.session));
      if (result.request.concurrentRequests) requestLines.push("Concurrent requests: " + result.request.concurrentRequests);
      if (result.request.model) requestLines.push("Model: " + result.request.model);
      if (result.request.body !== null && result.request.body !== undefined) {
        requestLines.push("Body: " + JSON.stringify(result.request.body));
      }
      requestLabel.textContent = "Simulated request";
      requestText.textContent = requestLines.join("\n");
      request.hidden = false;
      showStatus(result.tone, result.status || result.response.status + " " + statusLabel(result.response.status), result.title, result.detail);
      resultData.append(renderExchange(result));
      if (result.facts) resultData.append(renderFacts(result.facts));
      if (result.events) resultData.append(renderEvents(result.events));
    } catch (error) {
      if (run !== currentRun) return;
      console.error(error);
      showStatus("neutral", "Error", "Simulation interrupted", "Choose a payload to try again.");
    } finally {
      if (run === currentRun) response.setAttribute("aria-busy", "false");
    }
  });
}
