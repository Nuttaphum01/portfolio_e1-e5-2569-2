const http = require("node:http");
const { timingSafeEqual } = require("node:crypto");

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 3000);
const apiKey = process.env.API_KEY;
const maxBodyBytes = 4096;

if (!apiKey || apiKey.length < 16) {
  console.error("Set API_KEY to a secret of at least 16 characters before starting.");
  process.exit(1);
}

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("PORT must be an integer between 1 and 65535.");
  process.exit(1);
}

const expectedKey = Buffer.from(apiKey);
let wifiConfig = null;

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function isAuthorized(request) {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) {
    return false;
  }

  const providedKey = Buffer.from(authorization.slice(7));
  return providedKey.length === expectedKey.length
    && timingSafeEqual(providedKey, expectedKey);
}

async function readJsonBody(request) {
  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of request) {
    totalBytes += chunk.length;
    if (totalBytes > maxBodyBytes) {
      const error = new Error("Request body is too large.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("Request body must be valid JSON.");
    error.statusCode = 400;
    throw error;
  }
}

function validateWifiConfig(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "Body must be a JSON object.";
  }
  if (typeof body.ssid !== "string" || Buffer.byteLength(body.ssid, "utf8") < 1
      || Buffer.byteLength(body.ssid, "utf8") > 32) {
    return "ssid must be a string between 1 and 32 UTF-8 bytes.";
  }
  if (typeof body.password !== "string") {
    return "password must be a string (use an empty string for an open network).";
  }

  const passwordBytes = Buffer.byteLength(body.password, "utf8");
  if (passwordBytes !== 0 && (passwordBytes < 8 || passwordBytes > 63)
      && !(passwordBytes === 64 && /^[0-9a-fA-F]{64}$/.test(body.password))) {
    return "password must be empty, 8-63 UTF-8 bytes, or 64 hexadecimal characters.";
  }
  return null;
}

async function handleRequest(request, response) {
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  if (url.pathname !== "/api/wifi") {
    sendJson(response, 404, { error: "Not found." });
    return;
  }

  if (!isAuthorized(request)) {
    sendJson(response, 401, { error: "Unauthorized." });
    return;
  }

  if (request.method === "POST") {
    const body = await readJsonBody(request);
    const validationError = validateWifiConfig(body);
    if (validationError) {
      sendJson(response, 400, { error: validationError });
      return;
    }

    wifiConfig = { ssid: body.ssid, password: body.password };
    sendJson(response, 201, { message: "Wi-Fi configuration is ready for the ESP32." });
    return;
  }

  if (request.method === "GET") {
    if (!wifiConfig) {
      sendJson(response, 404, { error: "No Wi-Fi configuration is available." });
      return;
    }

    sendJson(response, 200, wifiConfig);
    return;
  }

  response.setHeader("Allow", "GET, POST");
  sendJson(response, 405, { error: "Method not allowed." });
}

const server = http.createServer((request, response) => {
  handleRequest(request, response).catch((error) => {
    if (response.headersSent) {
      response.destroy();
      return;
    }
    sendJson(response, error.statusCode || 500, {
      error: error.statusCode ? error.message : "Internal server error.",
    });
  });
});

server.listen(port, host, () => {
  console.log(`Wi-Fi configuration API listening on http://${host}:${port}`);
});

server.on("error", (error) => {
  console.error(`Unable to start server: ${error.message}`);
  process.exitCode = 1;
});