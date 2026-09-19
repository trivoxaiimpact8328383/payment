
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
    "Razorpay keys missing in Render Environment"
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

/* =====================================
   2. CORS CONFIGURATION
===================================== */

const allowedOrigins = [
  "https://trivoxaiimpact.com",
  "https://www.trivoxaiimpact.com"
];

if (process.env.FRONTEND_URL) {

  const extraOrigins =
    process.env.FRONTEND_URL
      .split(",")
      .map(url =>
        url.trim().replace(/\/$/, "")
      )
      .filter(Boolean);

  allowedOrigins.push(...extraOrigins);

}

const corsOptions = {

  origin: function(origin, callback) {

    if (
      !origin ||
      allowedOrigins.includes(origin)
    ) {

      return callback(null, true);

    }

    console.log(
      "CORS blocked:",
      origin
    );

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

};

app.use(cors(corsOptions));

/* =====================================
   3. RAZORPAY WEBHOOK

   Must come before express.json()
===================================== */

app.post(

  "/api/razorpay/webhook",

  express.raw({
    type: "application/json"
  }),

  async (req, res) => {

    try {

      if (!WEBHOOK_SECRET) {

        console.error(
          "Webhook secret missing"
        );

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

      const expectedSignature =
        crypto
          .createHmac(
            "sha256",
            WEBHOOK_SECRET
          )
          .update(req.body)
          .digest("hex");

      const valid =
        crypto.timingSafeEqual(

          Buffer.from(
            signature,
            "hex"
          ),

          Buffer.from(
            expectedSignature,
            "hex"
          )

        );

      if (!valid) {

        console.error(
          "Invalid webhook signature"
        );

        return res.sendStatus(400);

      }

      const event = JSON.parse(
        req.body.toString("utf8")
      );

      const payment =
        event.payload?.payment?.entity;

      const refund =
        event.payload?.refund?.entity;

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
            "CEZOO REFUND CREATED",
            {
              refund_id:
                refund?.id,

              payment_id:
                refund?.payment_id
            }
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

    } catch(error) {

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
   5. PRODUCT CATALOG

   ₹1 product included automatically.

   Add actual products using
   PRODUCT_CATALOG_JSON in Render.
===================================== */

let PRODUCT_CATALOG = {

  payment_1: {

    name: "CEZOO ₹1 Payment",

    price_paise: 100

  }

};

if (process.env.PRODUCT_CATALOG_JSON) {

  try {

    const additionalProducts =
      JSON.parse(
        process.env.PRODUCT_CATALOG_JSON
      );

    if (
      !additionalProducts ||
      typeof additionalProducts !== "object" ||
      Array.isArray(additionalProducts)
    ) {

      throw new Error(
        "Product catalog must be an object"
      );

    }

    PRODUCT_CATALOG = {

      ...additionalProducts,

      payment_1: {

        name: "CEZOO ₹1 Payment",

        price_paise: 100

      }

    };

  } catch(error) {

    throw new Error(
      "Invalid PRODUCT_CATALOG_JSON: " +
      error.message
    );

  }

}

/* =====================================
   6. HEALTH CHECK
===================================== */

app.get("/", (req, res) => {

  res.json({

    success: true,

    application: "CEZOO",

    service:
      "Razorpay Live Payment Backend",

    mode: "LIVE",

    status: "running"

  });

});

app.get(
  "/api/health",
  (req, res) => {

    res.json({

      success: true,

      status: "running",

      mode: "LIVE"

    });

  }
);

/* =====================================
   7. CREATE RAZORPAY ORDER

   POST /api/razorpay/create-order
===================================== */

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

        if (
          !item ||
          typeof item !== "object"
        ) {

          return res.status(400).json({

            success: false,

            message:
              "Invalid product item"

          });

        }

        const id =
          String(item.id || "");

        const quantity =
          item.quantity;

        const product =
          Object.prototype.hasOwnProperty.call(
            PRODUCT_CATALOG,
            id
          )
            ? PRODUCT_CATALOG[id]
            : null;

        if (!product) {

          return res.status(400).json({

            success: false,

            message:
              "Product not found: " + id

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
              "Invalid quantity"

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
            "Invalid payment amount"

        });

      }

      const receipt =
        "CZ_" +
        crypto.randomBytes(10)
          .toString("hex");

      const order =
        await razorpay.orders.create({

          amount:
            totalPaise,

          currency:
            "INR",

          receipt,

          partial_payment:
            false,

          notes: {

            application:
              "CEZOO",

            receipt,

            product_count:
              String(
                validatedItems.length
              )

          }

        });

      console.log(
        "CEZOO ORDER CREATED",
        {

          order_id:
            order.id,

          amount:
            totalPaise / 100,

          receipt

        }
      );

      return res.status(201).json({

        success: true,

        key:
          KEY_ID,

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
          "CEZOO Payment"

      });

    } catch(error) {

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

/* =====================================
   8. VERIFY PAYMENT

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

      } = req.body;

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

      /* VERIFY SIGNATURE */

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
            "Payment signature verification failed"

        });

      }

      /* FETCH ACTUAL PAYMENT */

      const payment =
        await razorpay.payments.fetch(
          razorpay_payment_id
        );

      /* FETCH ACTUAL ORDER */

      const order =
        await razorpay.orders.fetch(
          razorpay_order_id
        );

      /* VALIDATE ORDER */

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

      /* VALIDATE AMOUNT */

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

      /* VALIDATE CURRENCY */

      if (
        payment.currency !== "INR" ||
        order.currency !== "INR"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid payment currency"

        });

      }

      /* CHECK PAYMENT CAPTURE */

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

      /* SUCCESS */

      console.log(
        "CEZOO PAYMENT SUCCESSFUL",
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
          "Payment Successful!",

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

    } catch(error) {

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

/* =====================================
   9. ERROR HANDLER
===================================== */

app.use(
  (err, req, res, next) => {

    console.error(
      "Server error:",
      err.message
    );

    if (
      err.message ===
      "CORS not allowed"
    ) {

      return res.status(403).json({

        success: false,

        message:
          "Website origin not allowed"

      });

    }

    return res.status(500).json({

      success: false,

      message:
        "Internal server error"

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
      "CEZOO Backend Running"
    );

    console.log(
      "PORT:", PORT
    );

    console.log(
      "Razorpay LIVE Mode"
    );

    console.log(
      "CORS: trivoxaiimpact.com allowed"
    );

    console.log(
      "₹1 Payment Ready"
    );

    console.log(
      "================================"
    );

  }

);
