const express = require("express");
const otpauth = require("otpauth");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const memoryBase32ByUserId = new Map();

const TOTP_PARAMS = {
  issuer: "YOUR-CRM",
  issuerInLabel: true,
  label: "YOUR-CRM",
  digits: 6,
  period: 30,
  algorithm: "SHA1",
};

app.post("/generate", async (req, res) => {
  const { userId } = req.body;

  const secret = new otpauth.Secret({
    size: 20,
  });

  const totp = new otpauth.TOTP({
    ...TOTP_PARAMS,
    secret,
  });

  const otpauthurl = totp.toString();

  memoryBase32ByUserId.set(userId, {
    secret: secret.base32,
  });

  res.json({ qrCodeData: otpauthurl });

  ///

  console.debug({
    secret: secret.base32,
    otpauthurl,
  });
});

app.post("/verify", (req, res) => {
  const { userId, totpCode, window: maybeWindow } = req.body;

  const userTemp = memoryBase32ByUserId.get(userId);
  if (!userTemp) {
    return res.sendStatus(401);
  }

  const { secret } = userTemp;

  const totp = new otpauth.TOTP({
    ...TOTP_PARAMS,
    secret,
  });

  const selectedWindow = maybeWindow ?? 1;

  const validateWindow = totp.validate({
    token: totpCode,
    window: selectedWindow,
  });
  const validate =
    typeof validateWindow === "number"
      ? /** MUST USED: validateWindow !== null */
        validateWindow === selectedWindow
      : false;

  const remainingSeconds =
    totp.period - (Math.floor(Date.now() / 1000) % totp.period);

  {
    console.debug({
      userId,
      totpCode,
      suitableCode: totp.generate(),
      suitableCodeWithWindow: totp.generate({
        timestamp: Date.now() + selectedWindow * totp.period * 1000,
      }),
      validateWindow,
      validate,
      remainingSeconds,
      secret: userTemp.secret,
      window: selectedWindow,
    });
  }

  if (!validate) {
    return res.sendStatus(401);
  }

  res.sendStatus(200);
});

app.listen(3000, () => console.log("server started on port 3000"));
