const express = require("express");
const speakeasy = require("speakeasy");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const memoryBase32ByUserId = new Map();

app.post("/generate", async (req, res) => {
  const { userId } = req.body;
  const secretkeyForUser = speakeasy.generateSecret({
    issuer: "YOUR-CRM",
    name: "YOUR-CRM: " + userId,
    otpauth_url: true,
    length: 20,
  });

  console.log({
    userId,
    secret: secretkeyForUser.base32,
    url: secretkeyForUser.otpauth_url,
  });
  memoryBase32ByUserId.set(userId, secretkeyForUser.base32);

  res.json({ qrCodeData: secretkeyForUser.otpauth_url });
});

app.post("/verify", (req, res) => {
  const { userId, totpCode, window: maybeWindow } = req.body;

  const secretkeyForUser = memoryBase32ByUserId.get(userId);
  if (!secretkeyForUser) {
    return res.sendStatus(401);
  }

  const window = maybeWindow || 2;
  const verified = speakeasy.totp.verify({
    secret: secretkeyForUser,
    encoding: "base32",
    token: totpCode,
    window: window,
  });

  const delta = speakeasy.totp.verifyDelta({
    secret: secretkeyForUser,
    encoding: "base32",
    token: totpCode,
    window: window,
  });

  console.log({
    userId,
    totpCode,
    secretkeyForUser,
    verified,
    delta,
    window,
  });

  if (!verified) {
    return res.sendStatus(401);
  }

  res.sendStatus(200);

  // Сохраняем токен верификации в базу данных и используем его для дальнейшей работы.
});

app.listen(3000, () => console.log("server started on port 3000"));
