

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const app = express();

const PORT = process.env.PORT || 10000;

/* ======================================
   RAZORPAY LIVE CONFIGURATION
====================================== */

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
    "Please configure Razorpay LIVE keys"
  );
}

const razorpay = new Razorpay({
  key_id: KEY_ID,
  key_secret: KEY_SECRET
});

/* ======================================
   MIDDLEWARE
====================================== */

const allowedOrigins = (
  process.env.FRONTEND_URL || ""
)
  .split(",")
  .map(x => x.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {

      if (
        !origin ||
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error("Origin not allowed")
      );
    },

    methods: ["GET", "POST"],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

/* ======================================
   RAZORPAY WEBHOOK

   RAW BODY REQUIRED FOR SIGNATURE
====================================== */

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

      switch (event.event) {

        case "payment.captured":

          console.log(
            "CEZOO PAYMENT CAPTURED",
            {
              payment_id:
                payment?.id,

              order_id:
                payment?.order_id,

              amount:
                payment?.amount / 100,

              currency:
                payment?.currency,

              method:
                payment?.method
            }
          );

          break;

        case "payment.failed":

          console.log(
            "CEZOO PAYMENT FAILED",
            {
              payment_id:
                payment?.id,

              order_id:
                payment?.order_id
            }
          );

          break;

        case "refund.created":

          console.log(
            "CEZOO REFUND EVENT"
          );

          break;

        default:

          console.log(
            "Razorpay event:",
            event.event
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

app.use(express.json({
  limit: "100kb"
}));

/* ======================================
   CEZOO PRODUCT CATALOG

   Store trusted product prices on
   the server, not in customer HTML.

   Configure PRODUCT_CATALOG_JSON
   in Render.
====================================== */

let PRODUCT_CATALOG = {};

try {

  PRODUCT_CATALOG = JSON.parse(
    process.env.PRODUCT_CATALOG_JSON || "{}"
  );

} catch (error) {

  throw new Error(
    "Invalid PRODUCT_CATALOG_JSON"
  );

}

/* ======================================
   HEALTH CHECK
====================================== */

app.get("/", (req, res) => {

  res.json({

    success: true,

    app: "CEZOO",

    service:
      "Razorpay Payment Gateway",

    mode: "LIVE",

    status: "running"

  });

});

/* ======================================
   CREATE PRODUCT PAYMENT ORDER

   POST /api/razorpay/create-order
====================================== */

app.post(
  "/api/razorpay/create-order",

  async (req, res) => {

    try {

      const {
        items,
        customer_name,
        customer_phone
      } = req.body;

      if (
        !Array.isArray(items) ||
        items.length === 0 ||
        items.length > 100
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Valid product items required"

        });

      }

      let totalPaise = 0;

      const validatedItems = [];

      for (const item of items) {

        const id = String(
          item.id || ""
        );

        const quantity =
          item.quantity;

        const product =
          PRODUCT_CATALOG[id];

        if (!product) {

          return res.status(400).json({

            success: false,

            message:
              "Invalid product: " + id

          });

        }

        if (
          !Number.isSafeInteger(quantity) ||
          quantity < 1 ||
          quantity > 100
        ) {

          return res.status(400).json({

            success: false,

            message:
              "Invalid product quantity"

          });

        }

        const pricePaise =
          product.price_paise;

        if (
          !Number.isSafeInteger(pricePaise) ||
          pricePaise < 1
        ) {

          throw new Error(
            "Invalid server product price"
          );

        }

        totalPaise +=
          pricePaise * quantity;

        validatedItems.push({

          id,

          name:
            String(product.name || id),

          quantity,

          price:
            pricePaise / 100

        });

      }

      if (
        !Number.isSafeInteger(totalPaise) ||
        totalPaise < 100 ||
        totalPaise > 100000000
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid order total"

        });

      }

      const receipt =
        "CZ_" +
        crypto.randomBytes(10)
          .toString("hex");

      const order =
        await razorpay.orders.create({

          amount: totalPaise,

          currency: "INR",

          receipt,

          partial_payment: false,

          notes: {

            app: "CEZOO",

            receipt,

            product_count:
              String(validatedItems.length)

          }

        });

      console.log(
        "CEZOO ORDER CREATED",
        {
          order_id: order.id,
          amount: totalPaise / 100
        }
      );

      return res.status(201).json({

        success: true,

        key: KEY_ID,

        order_id:
          order.id,

        receipt,

        amount:
          order.amount,

        currency:
          "INR",

        products:
          validatedItems,

        total:
          totalPaise / 100,

        name:
          "CEZOO",

        description:
          "CEZOO Grocery Purchase"

      });

    } catch (error) {

      console.error(
        "Create order error:",
        error.message
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to create payment order"

      });

    }

  }
);

/* ======================================
   VERIFY PAYMENT

   POST /api/razorpay/verify
====================================== */

app.post(
  "/api/razorpay/verify",

  async (req, res) => {

    try {

      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = req.body;

      if (
        typeof razorpay_order_id !== "string" ||
        typeof razorpay_payment_id !== "string" ||
        typeof razorpay_signature !== "string"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Payment details missing"

        });

      }

      if (
        !/^[a-f0-9]{64}$/i.test(
          razorpay_signature
        )
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid payment signature"

        });

      }

      /* Verify Razorpay signature */

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

      const signatureValid =
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

      if (!signatureValid) {

        return res.status(400).json({

          success: false,

          message:
            "Payment signature mismatch"

        });

      }

      /* Fetch real payment from Razorpay */

      const payment =
        await razorpay.payments.fetch(
          razorpay_payment_id
        );

      /* Fetch real Razorpay order */

      const order =
        await razorpay.orders.fetch(
          razorpay_order_id
        );

      if (
        payment.order_id !==
        razorpay_order_id
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Payment order mismatch"

        });

      }

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

      /* Confirm money was captured */

      if (
        payment.status !== "captured"
      ) {

        return res.status(202).json({

          success: false,

          status:
            payment.status,

          message:
            "Payment not captured yet"

        });

      }

      console.log(
        "CEZOO PAYMENT VERIFIED",
        {
          order_id:
            razorpay_order_id,

          payment_id:
            razorpay_payment_id,

          amount:
            payment.amount / 100,

          method:
            payment.method
        }
      );

      return res.status(200).json({

        success: true,

        message:
          "CEZOO payment successful",

        status:
          "captured",

        order_id:
          razorpay_order_id,

        payment_id:
          razorpay_payment_id,

        amount:
          payment.amount / 100,

        currency:
          "INR",

        payment_method:
          payment.method

      });

    } catch (error) {

      console.error(
        "Payment verification error:",
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

/* ======================================
   SERVER START
====================================== */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "CEZOO Backend Running"
    );

    console.log(
      "PORT:", PORT
    );

    console.log(
      "Razorpay LIVE Mode"
    );

  }
);
