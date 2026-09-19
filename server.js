
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const app = express();

const PORT = process.env.PORT || 10000;

/* =====================================
   1. RAZORPAY LIVE KEYS
===================================== */

const KEY_ID =
  process.env.RAZORPAY_KEY_ID;

const KEY_SECRET =
  process.env.RAZORPAY_KEY_SECRET;

const WEBHOOK_SECRET =
  process.env.RAZORPAY_WEBHOOK_SECRET;

if (!KEY_ID || !KEY_SECRET) {
  throw new Error(
    "Razorpay keys missing in Render"
  );
}

if (!KEY_ID.startsWith("rzp_live_")) {
  throw new Error(
    "Razorpay LIVE key required"
  );
}

const razorpay = new Razorpay({
  key_id: KEY_ID,
  key_secret: KEY_SECRET
});

/* =====================================
   2. CORS FIX
===================================== */

const allowedOrigins = [
  "https://trivoxaiimpact.com",
  "https://www.trivoxaiimpact.com"
];

if (process.env.FRONTEND_URL) {

  allowedOrigins.push(
    ...process.env.FRONTEND_URL
      .split(",")
      .map(url =>
        url.trim().replace(/\/$/, "")
      )
      .filter(Boolean)
  );

}

app.use(cors({

  origin(origin, callback) {

    if (
      !origin ||
      allowedOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(
      new Error("CORS not allowed")
    );

  },

  methods: [
    "GET",
    "POST",
    "OPTIONS"
  ],

  allowedHeaders: [
    "Content-Type",
    "Authorization"
  ],

  optionsSuccessStatus: 204

}));

/* =====================================
   3. WEBHOOK
   BEFORE express.json()
===================================== */

app.post(
  "/api/razorpay/webhook",

  express.raw({
    type: "application/json"
  }),

  async (req, res) => {

    try {

      if (!WEBHOOK_SECRET) {
        return res.sendStatus(503);
      }

      const signature =
        req.headers["x-razorpay-signature"];

      if (
        typeof signature !== "string" ||
        !/^[a-f0-9]{64}$/i.test(signature)
      ) {
        return res.sendStatus(400);
      }

      const expected = crypto
        .createHmac(
          "sha256",
          WEBHOOK_SECRET
        )
        .update(req.body)
        .digest("hex");

      const valid =
        crypto.timingSafeEqual(
          Buffer.from(signature, "hex"),
          Buffer.from(expected, "hex")
        );

      if (!valid) {
        return res.sendStatus(400);
      }

      const event = JSON.parse(
        req.body.toString("utf8")
      );

      const payment =
        event.payload?.payment?.entity;

      if (
        event.event === "payment.captured"
      ) {

        console.log(
          "PAYMENT CAPTURED",
          {
            payment_id: payment?.id,
            order_id: payment?.order_id,
            amount: payment?.amount / 100,
            method: payment?.method
          }
        );

      }

      if (
        event.event === "payment.failed"
      ) {

        console.log(
          "PAYMENT FAILED",
          {
            payment_id: payment?.id,
            order_id: payment?.order_id
          }
        );

      }

      return res.status(200).json({
        success: true
      });

    } catch (error) {

      console.error(
        "Webhook error:",
        error.message
      );

      return res.sendStatus(500);

    }

  }
);

/* =====================================
   4. JSON MIDDLEWARE
===================================== */

app.use(
  express.json({
    limit: "100kb"
  })
);

/* =====================================
   5. HEALTH CHECK
===================================== */

app.get("/", (req, res) => {

  res.json({

    success: true,

    application: "CEZOO",

    service:
      "Razorpay Payment Backend",

    mode: "LIVE",

    status: "running",

    dynamic_payment: true

  });

});

/* =====================================
   6. CREATE DYNAMIC PAYMENT

   POST /api/razorpay/create-order
===================================== */

app.post(
  "/api/razorpay/create-order",

  async (req, res) => {

    try {

      const {
        amount,
        customer_name,
        customer_phone
      } = req.body || {};

      console.log(
        "Payment request received",
        {
          amount,
          type: typeof amount
        }
      );

      /* ACCEPT NUMBER OR NUMERIC STRING */

      if (
        amount === undefined ||
        amount === null ||
        typeof amount === "boolean" ||
        (
          typeof amount !== "number" &&
          typeof amount !== "string"
        ) ||
        (
          typeof amount === "string" &&
          amount.trim() === ""
        )
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Please enter a valid amount"

        });

      }

      const paymentAmount =
        Number(amount);

      /* VALIDATE AMOUNT */

      if (
        !Number.isFinite(paymentAmount) ||
        paymentAmount < 1 ||
        paymentAmount > 1000000
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Enter an amount between ₹1 and ₹10,00,000"

        });

      }

      /* CONVERT RUPEES TO PAISE */

      const amountPaise =
        Math.round(
          paymentAmount * 100
        );

      /* MAXIMUM TWO DECIMAL PLACES */

      if (
        Math.abs(
          paymentAmount * 100 -
          amountPaise
        ) > 0.000001
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Only two decimal places allowed"

        });

      }

      /* UNIQUE RECEIPT */

      const receipt =
        "CZ_" +
        crypto.randomBytes(10)
          .toString("hex");

      /* CREATE RAZORPAY ORDER */

      const order =
        await razorpay.orders.create({

          amount: amountPaise,

          currency: "INR",

          receipt,

          partial_payment: false,

          notes: {

            application: "CEZOO",

            payment_type:
              "Dynamic Amount",

            receipt

          }

        });

      console.log(
        "RAZORPAY ORDER CREATED",
        {
          order_id: order.id,
          amount: amountPaise / 100
        }
      );

      return res.status(201).json({

        success: true,

        key: KEY_ID,

        order_id: order.id,

        amount: order.amount,

        amount_rupees:
          amountPaise / 100,

        currency: "INR",

        receipt,

        name: "CEZOO",

        description:
          "CEZOO Payment"

      });

    } catch (error) {

      console.error(
        "CREATE ORDER ERROR:",
        error.message
      );

      if (error.error) {

        console.error(
          "Razorpay details:",
          error.error.description
        );

      }

      return res.status(500).json({

        success: false,

        message:
          "Unable to create Razorpay order"

      });

    }

  }
);

/* =====================================
   7. VERIFY PAYMENT

   POST /api/razorpay/verify
===================================== */

app.post(
  "/api/razorpay/verify",

  async (req, res) => {

    try {

      const {

        razorpay_order_id,

        razorpay_payment_id,

        razorpay_signature

      } = req.body || {};

      /* VALIDATE PAYMENT DETAILS */

      if (
        typeof razorpay_order_id !== "string" ||
        typeof razorpay_payment_id !== "string" ||
        typeof razorpay_signature !== "string"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Missing payment details"

        });

      }

      if (
        !/^order_[A-Za-z0-9]+$/.test(
          razorpay_order_id
        ) ||
        !/^pay_[A-Za-z0-9]+$/.test(
          razorpay_payment_id
        ) ||
        !/^[a-f0-9]{64}$/i.test(
          razorpay_signature
        )
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid payment details"

        });

      }

      /* GENERATE EXPECTED SIGNATURE */

      const expectedSignature =
        crypto
          .createHmac(
            "sha256",
            KEY_SECRET
          )
          .update(
            razorpay_order_id +
            "|" +
            razorpay_payment_id
          )
          .digest("hex");

      /* COMPARE SIGNATURES */

      const valid =
        crypto.timingSafeEqual(

          Buffer.from(
            expectedSignature,
            "hex"
          ),

          Buffer.from(
            razorpay_signature,
            "hex"
          )

        );

      if (!valid) {

        return res.status(400).json({

          success: false,

          message:
            "Payment signature mismatch"

        });

      }

      /* FETCH REAL PAYMENT */

      const payment =
        await razorpay.payments.fetch(
          razorpay_payment_id
        );

      /* FETCH REAL ORDER */

      const order =
        await razorpay.orders.fetch(
          razorpay_order_id
        );

      /* CHECK ORDER */

      if (
        payment.order_id !==
        order.id
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Payment order mismatch"

        });

      }

      /* CHECK AMOUNT */

      if (
        payment.amount !==
        order.amount
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Payment amount mismatch"

        });

      }

      /* CHECK CURRENCY */

      if (
        payment.currency !== "INR" ||
        order.currency !== "INR"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid currency"

        });

      }

      /* CHECK CAPTURE STATUS */

      if (
        payment.status !== "captured"
      ) {

        return res.status(202).json({

          success: false,

          status:
            payment.status,

          message:
            "Payment confirmation pending"

        });

      }

      /* PAYMENT SUCCESS */

      console.log(
        "CEZOO PAYMENT SUCCESSFUL",
        {

          order_id:
            order.id,

          payment_id:
            payment.id,

          amount:
            payment.amount / 100,

          method:
            payment.method

        }
      );

      return res.status(200).json({

        success: true,

        message:
          "Payment Successful!",

        status:
          "captured",

        order_id:
          order.id,

        payment_id:
          payment.id,

        amount:
          payment.amount / 100,

        currency:
          "INR",

        payment_method:
          payment.method

      });

    } catch (error) {

      console.error(
        "VERIFY PAYMENT ERROR:",
        error.message
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to verify payment"

      });

    }

  }
);

/* =====================================
   8. PAYMENT STATUS

   GET /api/razorpay/status/:orderId
===================================== */

app.get(
  "/api/razorpay/status/:orderId",

  async (req, res) => {

    try {

      const orderId =
        req.params.orderId;

      if (
        !/^order_[A-Za-z0-9]+$/.test(
          orderId
        )
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid order ID"

        });

      }

      const order =
        await razorpay.orders.fetch(
          orderId
        );

      const payments =
        await razorpay.orders.fetchPayments(
          orderId
        );

      const captured =
        payments.items.find(
          payment =>
            payment.status === "captured" &&
            payment.order_id === orderId &&
            payment.amount === order.amount &&
            payment.currency === order.currency
        );

      return res.json({

        success: true,

        order_id:
          order.id,

        status:
          captured
            ? "captured"
            : order.status,

        amount:
          order.amount / 100,

        currency:
          order.currency,

        payment_id:
          captured?.id || null,

        payment_method:
          captured?.method || null

      });

    } catch (error) {

      console.error(
        "PAYMENT STATUS ERROR:",
        error.message
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to check payment status"

      });

    }

  }
);

/* =====================================
   9. ERROR HANDLER
===================================== */

app.use(
  (err, req, res, next) => {

    console.error(
      "SERVER ERROR:",
      err.message
    );

    return res.status(
      err.message === "CORS not allowed"
        ? 403
        : 500
    ).json({

      success: false,

      message:
        err.message === "CORS not allowed"
          ? "Website origin not allowed"
          : "Internal server error"

    });

  }
);

/* =====================================
   10. START SERVER
===================================== */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "================================"
    );

    console.log(
      "CEZOO PAYMENT BACKEND RUNNING"
    );

    console.log(
      "PORT:", PORT
    );

    console.log(
      "RAZORPAY LIVE MODE"
    );

    console.log(
      "DYNAMIC PAYMENT ENABLED"
    );

    console.log(
      "CORS: trivoxaiimpact.com allowed"
    );

    console.log(
      "================================"
    );

  }
);
