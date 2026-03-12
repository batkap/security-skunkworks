const express = require("express");

const app = express();

const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----";

app.get("/health", (_req, res) => {
  res.json({ ok: true, keyLoaded: Boolean(PRIVATE_KEY) });
});

module.exports = app;

