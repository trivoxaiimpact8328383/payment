require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

/* =========================================
   1. ENVIRONMENT VARIABLES
========================================= */

const KEY_ID = process.env.RAZORPAY_KEY_ID;
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!KEY_ID || !KEY_SECRET) {
  throw new Error("Razorpay keys missing in Render");
}

if (!KEY_ID.startsWith("rzp_live_")) {
  throw new Error("Razorpay LIVE key required");
}

const razorpay = new Razorpay({
  key_id: KEY_ID,
  key_secret: KEY_SECRET
});

const trivoxDb =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
        {
          auth: {
            persistSession: false,
            autoRefreshToken: false
          }
        }
      )
    : null;

/* =========================================
   2. CORS
========================================= */

const allowedOrigins = [
  "https://trivoxaiimpact.com",
  "https://www.trivoxaiimpact.com"
];

if (process.env.FRONTEND_URL) {
  allowedOrigins.push(
    ...process.env.FRONTEND_URL
      .split(",")
      .map(url => url.trim().replace(/\/$/, ""))
      .filter(Boolean)
  );
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("CORS not allowed")
      );
    },

    methods: ["GET", "POST", "OPTIONS"],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ],

    optionsSuccessStatus: 204
  })
);

/* =========================================
   3. HELPERS
========================================= */

function validOrderId(value) {
  return (
    typeof value === "string" &&
    /^order_[A-Za-z0-9]+$/.test(value)
  );
}

function validPaymentId(value) {
  return (
    typeof value === "string" &&
    /^pay_[A-Za-z0-9]+$/.test(value)
  );
}

function validSignature(value) {
  return (
    typeof value === "string" &&
    /^[a-f0-9]{64}$/i.test(value)
  );
}

function verifyHmac(payload, signature, secret) {
  if (!validSignature(signature)) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(signature, "hex")
  );
}

function databaseReady(res) {
  if (trivoxDb) {
    return true;
  }

  res.status(503).json({
    success: false,
    message:
      "Supabase environment variables missing"
  });

  return false;
}

/* =========================================
   4. RAZORPAY WEBHOOK
   MUST BE BEFORE express.json()
========================================= */

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

      const valid = verifyHmac(
        req.body,
        signature,
        WEBHOOK_SECRET
      );

      if (!valid) {
        return res.sendStatus(400);
      }

      const event = JSON.parse(
        req.body.toString("utf8")
      );

      const payment =
        event.payload?.payment?.entity;

      if (event.event === "payment.captured") {
        console.log("PAYMENT CAPTURED", {
          payment_id: payment?.id,
          order_id: payment?.order_id,
          amount: payment?.amount / 100,
          method: payment?.method
        });

        /*
          Save Trivox course payment if the order
          belongs to the Trivox course table.

          Existing dynamic-payment orders are
          not changed.
        */

        if (
          trivoxDb &&
          payment?.order_id &&
          payment?.id
        ) {
          const { data: courseTx, error: lookupError } =
            await trivoxDb
              .from("trivox_course_payments")
              .select("razorpay_order_id")
              .eq(
                "razorpay_order_id",
                payment.order_id
              )
              .maybeSingle();

          if (lookupError) {
            console.error(
              "Course webhook lookup:",
              lookupError.message
            );

            return res.sendStatus(500);
          }

          if (courseTx) {
            await recordCapturedCoursePayment(
              payment.order_id,
              payment.id
            );
          }
        }
      }

      if (event.event === "payment.failed") {
        console.log("PAYMENT FAILED", {
          payment_id: payment?.id,
          order_id: payment?.order_id
        });
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

/* =========================================
   5. JSON MIDDLEWARE
========================================= */

app.use(
  express.json({
    limit: "100kb"
  })
);

/* =========================================
   6. HEALTH CHECK
========================================= */

app.get("/", (req, res) => {
  return res.json({
    success: true,
    application: "Trivox AI Impact",
    service: "Razorpay Payment Backend",
    mode: "LIVE",
    status: "running",
    dynamic_payment: true,
    course_payment: true,
    course_database_connected: Boolean(trivoxDb)
  });
});

/* =========================================
   7. EXISTING DYNAMIC PAYMENT
   POST /api/razorpay/create-order
========================================= */

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
        "Dynamic payment request:",
        {
          amount,
          type: typeof amount
        }
      );

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
          message: "Please enter a valid amount"
        });
      }

      const paymentAmount = Number(amount);

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

      const amountPaise = Math.round(
        paymentAmount * 100
      );

      if (
        Math.abs(
          paymentAmount * 100 - amountPaise
        ) > 0.000001
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Only two decimal places allowed"
        });
      }

      const receipt =
        "CZ_" +
        crypto.randomBytes(10).toString("hex");

      const order =
        await razorpay.orders.create({
          amount: amountPaise,
          currency: "INR",
          receipt,
          partial_payment: false,

          notes: {
            application: "CEZOO",
            payment_type: "Dynamic Amount",
            receipt
          }
        });

      console.log(
        "DYNAMIC ORDER CREATED",
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
        amount_rupees: amountPaise / 100,
        currency: "INR",
        receipt,
        name: "CEZOO",
        description: "CEZOO Payment"
      });

    } catch (error) {
      console.error(
        "CREATE ORDER ERROR:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to create Razorpay order"
      });
    }
  }
);

/* =========================================
   8. EXISTING PAYMENT VERIFICATION
   POST /api/razorpay/verify
========================================= */

app.post(
  "/api/razorpay/verify",

  async (req, res) => {
    try {
      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = req.body || {};

      if (
        !validOrderId(razorpay_order_id) ||
        !validPaymentId(razorpay_payment_id) ||
        !validSignature(razorpay_signature)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid payment details"
        });
      }

      const valid = verifyHmac(
        razorpay_order_id +
          "|" +
          razorpay_payment_id,

        razorpay_signature,
        KEY_SECRET
      );

      if (!valid) {
        return res.status(400).json({
          success: false,
          message:
            "Payment signature mismatch"
        });
      }

      const payment =
        await razorpay.payments.fetch(
          razorpay_payment_id
        );

      const order =
        await razorpay.orders.fetch(
          razorpay_order_id
        );

      if (
        payment.order_id !== order.id
      ) {
        return res.status(400).json({
          success: false,
          message: "Payment order mismatch"
        });
      }

      if (
        payment.amount !== order.amount
      ) {
        return res.status(400).json({
          success: false,
          message: "Payment amount mismatch"
        });
      }

      if (
        payment.currency !== "INR" ||
        order.currency !== "INR"
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid currency"
        });
      }

      if (payment.status !== "captured") {
        return res.status(202).json({
          success: false,
          status: payment.status,
          message:
            "Payment confirmation pending"
        });
      }

      console.log(
        "DYNAMIC PAYMENT SUCCESSFUL",
        {
          order_id: order.id,
          payment_id: payment.id,
          amount: payment.amount / 100,
          method: payment.method
        }
      );

      return res.status(200).json({
        success: true,
        message: "Payment Successful!",
        status: "captured",
        order_id: order.id,
        payment_id: payment.id,
        amount: payment.amount / 100,
        currency: "INR",
        payment_method: payment.method
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

/* =========================================
   9. EXISTING PAYMENT STATUS
   GET /api/razorpay/status/:orderId
========================================= */

app.get(
  "/api/razorpay/status/:orderId",

  async (req, res) => {
    try {
      const orderId =
        req.params.orderId;

      if (!validOrderId(orderId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid order ID"
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
        order_id: order.id,

        status: captured
          ? "captured"
          : order.status,

        amount: order.amount / 100,
        currency: order.currency,

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

/* =========================================
   10. TRIVOX COURSE PAYMENT HELPER
========================================= */

async function recordCapturedCoursePayment(
  orderId,
  paymentId
) {
  if (!trivoxDb) {
    throw new Error(
      "Supabase not configured"
    );
  }

  const {
    data: transaction,
    error: findError
  } = await trivoxDb
    .from("trivox_course_payments")
    .select("*")
    .eq("razorpay_order_id", orderId)
    .single();

  if (findError || !transaction) {
    throw new Error(
      "Course payment order not found"
    );
  }

  const [payment, order] =
    await Promise.all([
      razorpay.payments.fetch(paymentId),
      razorpay.orders.fetch(orderId)
    ]);

  if (
    payment.status !== "captured" ||
    payment.order_id !== orderId ||
    order.id !== orderId ||
    payment.amount !==
      transaction.amount_paise ||
    order.amount !==
      transaction.amount_paise ||
    payment.currency !== "INR" ||
    order.currency !== "INR"
  ) {
    throw new Error(
      "Payment not captured or amount mismatch"
    );
  }

  const {
    error: updateError
  } = await trivoxDb
    .from("trivox_course_payments")
    .update({
      status: "captured",
      razorpay_payment_id: payment.id,
      payment_method: payment.method,
      captured_at:
        new Date().toISOString()
    })
    .eq("razorpay_order_id", orderId);

  if (updateError) {
    throw updateError;
  }

  console.log(
    "TRIVOX COURSE PAYMENT SAVED",
    {
      course_id: transaction.course_id,
      order_id: orderId,
      payment_id: payment.id
    }
  );

  return {
    success: true,
    status: "captured",

    course_id:
      transaction.course_id,

    course_title:
      transaction.course_title,

    order_id: order.id,
    payment_id: payment.id,

    amount:
      payment.amount / 100,

    currency: "INR",

    payment_method:
      payment.method
  };
}

/* =========================================
   11. CREATE TRIVOX COURSE ORDER

   POST
   /api/razorpay/course/create-order

   BODY:
   {
     "course_id": 1
   }
========================================= */

app.post(
  "/api/razorpay/course/create-order",

  async (req, res) => {
    try {
      if (!databaseReady(res)) {
        return;
      }

      const courseId =
        Number(req.body?.course_id);

      if (
        !Number.isSafeInteger(courseId) ||
        courseId < 1
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid course ID"
        });
      }

      /*
        Price comes from Supabase.

        Do not accept course price
        from the browser.
      */

      const {
        data: course,
        error: courseError
      } = await trivoxDb
        .from("course_catalog")
        .select(
          "id,title,price,status"
        )
        .eq("id", courseId)
        .single();

      if (courseError || !course) {
        console.error(
          "Course lookup error:",
          courseError?.message
        );

        return res.status(404).json({
          success: false,
          message: "Course not found"
        });
      }

      if (
        String(
          course.status || ""
        ).toLowerCase() !== "available"
      ) {
        return res.status(400).json({
          success: false,
          message: "Course unavailable"
        });
      }

      const rupees =
        Number(course.price);

      const amountPaise =
        Math.round(rupees * 100);

      if (
        !Number.isFinite(rupees) ||
        amountPaise < 100 ||
        amountPaise > 100000000 ||
        Math.abs(
          rupees * 100 - amountPaise
        ) > 0.000001
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid course price"
        });
      }

      const receipt =
        "TV_" +
        crypto.randomBytes(9)
          .toString("hex");

      const order =
        await razorpay.orders.create({
          amount: amountPaise,
          currency: "INR",
          receipt,
          partial_payment: false,

          notes: {
            application:
              "Trivox AI Impact",

            course_id:
              String(course.id)
          }
        });

      /*
        Save created order BEFORE
        returning it to frontend.
      */

      const {
        error: saveError
      } = await trivoxDb
        .from("trivox_course_payments")
        .insert({
          course_id: course.id,

          course_title:
            course.title,

          amount_paise:
            amountPaise,

          currency: "INR",

          razorpay_order_id:
            order.id,

          status: "created"
        });

      if (saveError) {
        console.error(
          "Course order save error:",
          saveError.message
        );

        return res.status(500).json({
          success: false,

          message:
            "Unable to save course order. Do not pay."
        });
      }

      console.log(
        "TRIVOX COURSE ORDER CREATED",
        {
          course_id: course.id,
          order_id: order.id,
          amount: amountPaise / 100
        }
      );

      return res.status(201).json({
        success: true,

        key: KEY_ID,

        order_id:
          order.id,

        amount:
          order.amount,

        currency:
          "INR",

        course_id:
          course.id,

        course_title:
          course.title
      });

    } catch (error) {
      console.error(
        "TRIVOX CREATE ORDER ERROR:",
        error.message
      );

      return res.status(500).json({
        success: false,

        message:
          "Unable to create course payment"
      });
    }
  }
);

/* =========================================
   12. VERIFY TRIVOX COURSE PAYMENT

   POST
   /api/razorpay/course/verify

   BODY:
   {
     "razorpay_order_id": "...",
     "razorpay_payment_id": "...",
     "razorpay_signature": "..."
   }
========================================= */

app.post(
  "/api/razorpay/course/verify",

  async (req, res) => {
    try {
      if (!databaseReady(res)) {
        return;
      }

      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = req.body || {};

      if (
        !validOrderId(
          razorpay_order_id
        ) ||
        !validPaymentId(
          razorpay_payment_id
        ) ||
        !validSignature(
          razorpay_signature
        )
      ) {
        return res.status(400).json({
          success: false,

          message:
            "Invalid payment details"
        });
      }

      const valid = verifyHmac(
        razorpay_order_id +
          "|" +
          razorpay_payment_id,

        razorpay_signature,
        KEY_SECRET
      );

      if (!valid) {
        return res.status(400).json({
          success: false,

          message:
            "Payment signature mismatch"
        });
      }

      const result =
        await recordCapturedCoursePayment(
          razorpay_order_id,
          razorpay_payment_id
        );

      return res.status(200).json(
        result
      );

    } catch (error) {
      console.error(
        "TRIVOX VERIFY ERROR:",
        error.message
      );

      return res.status(409).json({
        success: false,

        message:
          "Payment confirmation pending. Check transaction before retrying."
      });
    }
  }
);

/* =========================================
   13. ERROR HANDLER
========================================= */

app.use(
  (err, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      err.message
    );

    const corsError =
      err.message ===
      "CORS not allowed";

    return res.status(
      corsError ? 403 : 500
    ).json({
      success: false,

      message: corsError
        ? "Website origin not allowed"
        : "Internal server error"
    });
  }
);

/* =========================================
   14. START SERVER
========================================= */

app.listen(
  PORT,
  "0.0.0.0",

  () => {
    console.log(
      "================================"
    );

    console.log(
      "TRIVOX PAYMENT BACKEND RUNNING"
    );

    console.log(
      "PORT:",
      PORT
    );

    console.log(
      "RAZORPAY LIVE MODE"
    );

    console.log(
      "DYNAMIC PAYMENT ENABLED"
    );

    console.log(
      "COURSE PAYMENT ENABLED"
    );

    console.log(
      "SUPABASE:",
      trivoxDb
        ? "CONFIGURED"
        : "NOT CONFIGURED"
    );

    console.log(
      "================================"
    );
  }
);
