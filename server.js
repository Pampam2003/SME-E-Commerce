// server.js
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const moment = require('moment');

const app = express();

// Ensure the uploads folder exists
const uploadPath = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
  console.log('✅ Uploads folder created at:', uploadPath);
}

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(express.json({ type: 'application/json' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------- IMAGE UPLOAD CONFIG ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// ---------- DATABASE CONNECTION (POOL) ----------
const db = mysql.createPool({
  connectionLimit: 10,
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'sme_ecommerce',
  multipleStatements: false
});

// quick test of connection pool
db.query('SELECT 1', (err) => {
  if (err) console.error('❌ Database connection failed:', err);
  else console.log('✅ Connected to MySQL Database (pool).');
});

// PUT THIS NEAR THE TOP — AFTER db pool, BEFORE any routes
function logActivity(userId = null, userEmail = null, action, details = '') {
  console.log('LOGGING ACTIVITY →', { userEmail, action, details });  // ← THIS WILL SHOW IN TERMINAL

  const cleanDetails = String(details).substring(0, 500);
  const sql = `INSERT INTO activity_logs 
               (user_id, user_email, action, details, timestamp) 
               VALUES (?, ?, ?, ?, NOW())`;

  db.query(sql, [userId, userEmail || null, action, cleanDetails], (err) => {
    if (err) {
      console.error('FAILED TO SAVE LOG TO DB:', err);
    } else {
      console.log('LOG SAVED TO DATABASE SUCCESSFULLY');
    }
  });
}

// ---------- MPESA CONFIG ----------
const MPESA = {
  consumerKey: '8boQGEowrYWDTDJXSrc5jqjYAEQextOcrjzA4j0BRjaQmg1k',
  consumerSecret: 'VXm6ys83SgZ6EuasSF9DRsZT1TZobDnQ7JHhSvTxDVJoypj9bmCGidr0LkfDAKAA',
  shortcode: '174379',
  passkey: 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919',
  callbackUrl: 'https://treasonable-matted-rashida.ngrok-free.dev/mpesa/callback',
  environment: 'sandbox'
};

// Function to get OAuth Token
async function getOAuthToken() {
  const auth = Buffer.from(`${MPESA.consumerKey}:${MPESA.consumerSecret}`).toString('base64');
  const url = MPESA.environment === 'sandbox'
    ? 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    : 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

  try {
    const res = await axios.get(url, {
      headers: { Authorization: `Basic ${auth}` }
    });
    return res.data.access_token;
  } catch (err) {
    console.error('OAuth Token Error:', err.response?.data || err.message);
    throw err;
  }
}

// STK query function
async function queryStkStatus(checkoutRequestID, token) {
  const timestamp = moment().format('YYYYMMDDHHmmss');
  const password = Buffer.from(`${MPESA.shortcode}${MPESA.passkey}${timestamp}`).toString('base64');

  const payload = {
    BusinessShortCode: MPESA.shortcode,
    Password: password,
    Timestamp: timestamp,
    CheckoutRequestID: checkoutRequestID
  };

  try {
    const res = await axios.post(
      'https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query',
      payload,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    return res.data;
  } catch (err) {
    // return null on error (polling will continue until max attempts)
    console.error('Query error:', err.response?.data || err.message);
    return null;
  }
}

// ---------- ROUTES ----------

// STK Push Route
app.post('/mpesa/stkpush', async (req, res) => {
  const { phone, amount, order_id } = req.body;
  if (!phone || !amount || !order_id) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    const token = await getOAuthToken();
    const timestamp = moment().format('YYYYMMDDHHmmss');
    const password = Buffer.from(`${MPESA.shortcode}${MPESA.passkey}${timestamp}`).toString('base64');

    const payload = {
      BusinessShortCode: MPESA.shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: amount,
      PartyA: phone,
      PartyB: MPESA.shortcode,
      PhoneNumber: phone,
      CallBackURL: MPESA.callbackUrl,
      AccountReference: `Order${order_id}`,
      TransactionDesc: `Payment for Order #${order_id}`
    };

    const response = await axios.post(
      'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      payload,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const requestId = response.data?.CheckoutRequestID;
    if (!requestId) {
      console.error('No CheckoutRequestID in response:', response.data);
      return res.status(500).json({ error: 'Failed to initiate STK Push' });
    }

    // Save CheckoutRequestID (non-blocking)
    db.query('UPDATE orders SET mpesa_request_id = ? WHERE id = ?', [requestId, order_id], (err) => {
      if (err) console.error('Save request ID error:', err);
      else console.log(`Saved CheckoutRequestID: ${requestId} for Order #${order_id}`);
    });

    res.json({ success: true, message: 'STK Push sent!' });

    // START POLLING (background loop inside this request, but non-blocking to client)
    let attempts = 0;
    const maxAttempts = 20;
    const pollInterval = 3000; // 3s

    const poll = setInterval(async () => {
      attempts++;
      if (attempts >= maxAttempts) {
        clearInterval(poll);
        console.log(`Polling ended for ${requestId} after ${attempts} attempts`);
        return;
      }

      try {
        const queryRes = await queryStkStatus(requestId, token);
        // Safaricom returns ResultCode as number (0 for success)
        if (queryRes && (queryRes.ResultCode === 0 || queryRes.ResultCode === '0')) {
          clearInterval(poll);

          // For safety, attempt to find receipt in CallbackMetadata if present
          let receipt = null;
          if (queryRes.CallbackMetadata?.Item && Array.isArray(queryRes.CallbackMetadata.Item)) {
            const recObj = queryRes.CallbackMetadata.Item.find(i => i.Name === 'MpesaReceiptNumber' || i.name === 'MpesaReceiptNumber');
            receipt = recObj?.Value || null;
          }

          // Update order to Paid
          db.query(
            `UPDATE orders SET status = 'Paid', mpesa_amount = ?, mpesa_phone = ? WHERE mpesa_request_id = ?`,
            [amount, phone, requestId],
            (err) => {
              if (err) console.error('Poll update error:', err);
              else console.log(`POLL SUCCESS: Order #${order_id} PAID! Receipt: ${receipt || 'N/A'}`);
            }
          );
        }
      } catch (err) {
        console.error('Polling error:', err?.message || err);
      }
    }, pollInterval);

  } catch (err) {
    console.error('STK Push Error:', err.response?.data || err.message || err);
    res.status(500).json({ error: 'STK Push failed' });
  }
});

// MPESA Callback
app.post('/mpesa/callback', (req, res) => {
  const callback = req.body;
  console.log('CALLBACK:', JSON.stringify(callback, null, 2));

  const stk = callback.Body?.stkCallback;
  if (!stk || stk.ResultCode !== 0) {
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  const requestId = stk.CheckoutRequestID;
  let receipt = null;
  let phone = null;
  let amount = null;

  if (stk.CallbackMetadata?.Item) {
    stk.CallbackMetadata.Item.forEach(i => {
      if (i.Name === 'MpesaReceiptNumber') receipt = i.Value;
      if (i.Name === 'PhoneNumber') phone = i.Value;
      if (i.Name === 'Amount') amount = i.Value;
    });
  }

  db.query(
    `UPDATE orders SET status = 'Paid', mpesa_receipt = ?, mpesa_phone = ?, mpesa_amount = ? WHERE mpesa_request_id = ?`,
    [receipt, phone, amount, requestId],
    (err) => {
      if (err) console.error('Callback update failed:', err);
      else console.log(`CALLBACK SUCCESS: Order paid! Receipt: ${receipt}`);
    }
  );

  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
});
// AUTH — ONLY ONE LOGIN & REGISTER
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err || !results.length) {
      return res.json({ message: 'Invalid credentials' });
    }

    const user = results[0];

    // CHECK IF SUSPENDED
    if (user.status === 'suspended') {
      logActivity(user.id, 'Login Attempt (Suspended)', `Blocked login for suspended user: ${email}`);
      return res.json({ 
        message: 'Your account has been suspended. Please contact support.' 
      });
    }

    if (password !== user.password) {
      return res.json({ message: 'Invalid credentials' });
    }

    res.json({
      message: 'Login successful',
      role: user.role?.trim() || 'customer',
      name: user.name || email.split('@')[0],
      email: user.email,
      id: user.id
    });

    logActivity(user.id, 'Login', `User logged in: ${email}`);
  });
});

app.post('/register', (req, res) => {
  const { name, email, password, role = 'customer' } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (results?.length) return res.json({ message: 'Email already exists' });

    db.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, password, role], (err, result) => {
      if (err) return res.status(500).json({ message: 'Registration failed' });
      logActivity(result.insertId, 'User Registered', `New user: ${name} (${email})`);
      res.json({ message: 'Registration successful!' });
    });
  });
});
//// ---------- PRODUCTS ----------
app.post('/add-product', upload.single('image'), (req, res) => {
  const { name, category, description, price, quantity } = req.body;

  if (!name || !category || !description || !price || !quantity) {
    return res.status(400).json({ message: 'All fields are required!' });
  }

  const priceNum = parseFloat(price);
  const quantityNum = parseInt(quantity, 10);

  let imagePath = '';
  if (req.file && req.file.filename) {
    imagePath = '/uploads/' + req.file.filename;
  }

  const sql = 'INSERT INTO products (name, category, description, price, quantity, image) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(sql, [name, category, description, priceNum, quantityNum, imagePath], (err) => {
    if (err) {
      console.error('Add product error:', err);
      return res.status(500).json({ message: 'Server error while adding product' });
    }
    res.json({ message: '✅ Product added successfully!' });
  });
});

app.get('/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch products' });
    res.json(results || []);
  });
});

app.get('/search-products', (req, res) => {
  const { category, keyword } = req.query;
  let sql = 'SELECT * FROM products WHERE 1=1';
  const params = [];

  if (category) {
    sql += ' AND category LIKE ?';
    params.push(`%${category}%`);
  }
  if (keyword) {
    sql += ' AND name LIKE ?';
    params.push(`%${keyword}%`);
  }

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to search products' });
    res.json(results || []);
  });
});

app.delete('/delete-product/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT image FROM products WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to delete product' });
    if (!results || results.length === 0) return res.status(404).json({ message: 'Product not found' });

    const imagePath = results[0]?.image;
    if (imagePath) {
      // ensure we only use the filename portion to avoid path issues
      const filename = path.basename(imagePath);
      const fixedPath = path.join(__dirname, 'uploads', filename);
      fs.unlink(fixedPath, (e) => { if (e && e.code !== 'ENOENT') console.error('Unlink error:', e); });
    }

    db.query('DELETE FROM products WHERE id = ?', [id], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to delete product' });
      res.json({ message: '✅ Product deleted successfully!' });
    });
  });
});

// ---------- USERS ----------
app.get('/users', (req, res) => {
  db.query('SELECT id, name, email, role, created_at, status FROM users ORDER BY id DESC', (err, results) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ message: 'Failed to fetch users' });
    }
    res.json(results || []);
  });
});

/// ---------- REVIEWS (WITH FULL ACTIVITY LOG) ----------
app.post('/review', (req, res) => {
  const { product_id, customer_email, review, rating } = req.body;

  if (!product_id || !customer_email || !review || !rating) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  if (rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Rating must be between 1 and 5' });
  }

  // Optional: Get product name for richer logs (highly recommended!)
  db.query('SELECT name FROM products WHERE id = ?', [product_id], (err, prodResult) => {
    const productName = prodResult?.[0]?.name || `Product ID: ${product_id}`;

    const sql = 'INSERT INTO reviews (product_id, customer_email, review, rating) VALUES (?, ?, ?, ?)';
    db.query(sql, [product_id, customer_email, review, rating], (err, result) => {
      if (err) {
        console.error('Review insert error:', err);
        return res.status(500).json({ message: 'Failed to submit review' });
      }

      // THIS IS THE GOLD LOG
      logActivity(
        null,                    // user_id (we don't have it here, but email is enough)
        customer_email,         // who submitted
        'Review Submitted',     // action
        `${rating} stars on "${productName}" | "${review.substring(0, 100)}${review.length > 100 ? '...' : ''}"`
      );

      res.json({ message: 'Review submitted successfully!' });
    });
  });
});

app.get('/reviews', (req, res) => {
  const sql = `
    SELECT r.id, r.product_id, r.customer_email, r.review, r.reply, r.rating, p.name AS product_name
    FROM reviews r
    JOIN products p ON r.product_id = p.id
    ORDER BY r.created_at DESC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch reviews' });
    res.json(results || []);
  });
});

// ---------- DELIVERED ORDERS ----------
app.get('/delivered-orders', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  const sql = `
    SELECT o.product_id, p.name AS product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.customer_id = (SELECT id FROM users WHERE email = ?) AND o.status = 'Delivered'
  `;
  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch delivered products' });
    res.json(results || []);
  });
});

// ---------- ORDERS ----------
app.post('/orders', (req, res) => {
  const { customer_id, product_id, quantity } = req.body;
  if (!customer_id || !product_id || !quantity) return res.status(400).json({ message: 'All fields are required!' });

  db.query('SELECT price FROM products WHERE id = ?', [product_id], (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (!results || results.length === 0) return res.status(404).json({ message: 'Product not found' });

    const price = parseFloat(results[0].price);
    const total_price = price * parseInt(quantity, 10);

    db.query('INSERT INTO orders (customer_id, product_id, quantity, total_price, status) VALUES (?, ?, ?, ?, ?)',
      [customer_id, product_id, quantity, total_price, 'Pending'], (err2) => {
        if (err2) return res.status(500).json({ message: 'Failed to create order' });
        res.json({ message: '✅ Order created successfully!' });
      });
  });
});

app.get('/orders', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const sql = `
    SELECT 
      o.id AS order_id,
      p.name AS product_name,
      o.quantity,
      o.total_price,
      o.status,
      o.created_at AS order_date,
      o.mpesa_receipt AS receipt
    FROM orders o
    JOIN users u ON o.customer_id = u.id
    JOIN products p ON o.product_id = p.id
    WHERE u.email = ?
    ORDER BY o.created_at DESC
  `;

  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error('Orders fetch error:', err);
      return res.status(500).json([]);
    }
    res.json(results || []);
  });
});

app.get('/orders/:id', (req, res) => {
  const lookupId = req.params.id;

  const sql = `
    SELECT status FROM orders 
    WHERE id = ? OR mpesa_request_id = ?
    ORDER BY id DESC LIMIT 1
  `;

  db.query(sql, [lookupId, lookupId], (err, results) => {
    if (err || !results || results.length === 0) {
      return res.json({ status: 'Pending' });
    }
    res.json({ status: results[0].status });
  });
});

app.put('/orders/:id', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  db.query('UPDATE orders SET status = ? WHERE id = ?', [status, id], (err) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json({ message: `Order #${id} updated to ${status}` });
  });
});
// ---------- CHECKOUT (WITH PROPER ACTIVITY LOG) ----------
app.post('/checkout', (req, res) => {
  const { email, cart, phone } = req.body;

  if (!email || !cart || !Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ message: 'Invalid request: missing email or cart' });
  }

  for (const item of cart) {
    if (!item.id || !item.qty || !item.price || item.qty < 1 || item.price <= 0) { 
      return res.status(400).json({ message: 'Invalid cart item' });
    }
  }

  db.query('SELECT id FROM users WHERE email = ?', [email], (err, users) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (!users || users.length === 0) return res.status(404).json({ message: 'User not found' });

    const customer_id = users[0].id;
    let firstOrderId = null;
    let totalAmount = 0;

    // Calculate total for logging
    cart.forEach(item => {
      totalAmount += parseInt(item.qty) * parseFloat(item.price);
    });

    const insertItem = (index) => {
      if (index >= cart.length) {
        // ORDER SUCCESSFULLY PLACED → LOG IT NOW!
        logActivity(
          customer_id,
          email,
          'Order Placed',
          `Order #${firstOrderId} | ${cart.length} item(s) | Total: Ksh ${totalAmount.toFixed(2)} | Phone: ${phone || 'Not provided'}`
        );

        return res.json({ 
          message: 'Checkout successful!', 
          order_id: firstOrderId 
        });
      }

      const item = cart[index];
      const qty = parseInt(item.qty, 10);
      const price = parseFloat(item.price);
      const total = qty * price;

      if (isNaN(total)) {
        return res.status(400).json({ message: 'Invalid price or quantity' });
      }

      db.query(
        `INSERT INTO orders (customer_id, product_id, quantity, total_price, mpesa_phone, status)
         VALUES (?, ?, ?, ?, ?, 'Pending')`,
        [customer_id, item.id, qty, total, phone],
        (err, result) => {
          if (err) {
            console.error('DB Insert Error:', err);
            return res.status(500).json({ message: 'Failed to save order: ' + err.message });
          }
          if (index === 0) firstOrderId = result.insertId;
          insertItem(index + 1);
        }
      );
    };

    insertItem(0);
  });
});
// ========== ADMIN: GET ALL ORDERS ==========
app.get('/admin-orders', (req, res) => {
  const sql = `
    SELECT 
      o.id AS order_id,
      u.name AS customer_name,
      u.email AS customer_email,
      p.name AS product_name,
      o.quantity,
      o.total_price,
      o.status,
      o.mpesa_phone,
      o.created_at
    FROM orders o
    JOIN users u ON o.customer_id = u.id
    JOIN products p ON o.product_id = p.id
    ORDER BY o.created_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Admin orders error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results || []);
  });
});
// SME LISTINGS — FINAL 100% WORKING VERSION
app.get('/sme-listings', (req, res) => {
  const filter = req.query.status || 'pending';

  let sql = 'SELECT id, business_name, owner_name, owner_email, category, status FROM smes';
  const params = [];

  if (filter !== 'all') {
    sql += ' WHERE status = ?';
    params.push(filter === 'approved' ? 1 : 0);
  }

  sql += ' ORDER BY id DESC';

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error('SME Listings DB Error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    const list = results.map(r => ({
      id: r.id,
      business_name: r.business_name || '—',
      owner_name: r.owner_name || '—',
      owner_email: r.owner_email,
      category: r.category || '—',
      status: r.status === 1 ? 'approved' : 'pending'
    }));

    res.json(list);
  });
});

// ========== SME: UPDATE ORDER STATUS (Shipped → Delivered) ==========
app.post('/sme/update-order-status', (req, res) => {
  const { order_id, status, sme_email } = req.body;

  // Validate input
  if (!order_id || !status || !sme_email) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  if (!['Shipped', 'Delivered'].includes(status)) {
    return res.status(400).json({ message: 'Invalid status. Use Shipped or Delivered' });
  }

  // Only allow transition: Paid → Shipped → Delivered
  const allowedTransitions = {
    'Paid': ['Shipped'],
    'Shipped': ['Delivered']
  };

  

  // First check current status
  db.query('SELECT o.status, s.owner_email FROM orders o JOIN products p ON o.product_id = p.id JOIN smes s ON p.sme_id = s.id WHERE o.id = ?', 
    [order_id], 
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ message: 'Order not found or not yours' });
      }

      const order = results[0];
      if (order.owner_email !== sme_email) {
        return res.status(403).json({ message: 'Unauthorized' });
      }

      const currentStatus = order.status;
      if (!allowedTransitions[currentStatus]?.includes(status)) {
        return res.status(400).json({ 
          message: `Cannot change from ${currentStatus} to ${status}` 
        });
      }

      // Update status
      db.query('UPDATE orders SET status = ? WHERE id = ?', [status, order_id], (err, result) => {
        if (err || result.affectedRows === 0) {
          return res.status(500).json({ message: 'Failed to update status' });
        }

        res.json({ 
          message: `Order #${order_id} is now ${status}!` 
        });
      });
    }
  );
});

// ========== SME: MY REVIEWS (100% WORKING & FIXED) ==========
app.get('/sme/my-reviews', (req, res) => {
  const { sme_email } = req.query;
  if (!sme_email) return res.status(400).json([]);

  const sql = `
    SELECT 
      r.id,
      r.rating,
      r.review,
      r.created_at,
      p.name AS product_name,
      u.name AS customer_name,
      u.email AS customer_email
    FROM reviews r
    JOIN products p ON r.product_id = p.id
    JOIN smes s ON p.sme_id = s.id
    LEFT JOIN users u ON r.customer_email = u.email
    WHERE s.owner_email = ?
    ORDER BY r.created_at DESC
  `;

  db.query(sql, [sme_email], (err, results) => {
    if (err) {
      console.error('SME Reviews Error:', err);
      return res.status(500).json([]);
    }
    res.json(results || []);
  });
});

// ---------- ACTIVITY LOGS ----------
app.get('/activity-logs', (req, res) => {
  if (req.query.date) {
    const sql = `
      SELECT * FROM activity_logs 
      WHERE DATE(timestamp) = ?
      ORDER BY timestamp DESC
    `;
    db.query(sql, [req.query.date], (err, results) => {
      if (err) return res.status(500).json([]);
      res.json(results || []);
    });
    return;
  }

  const sql = `
    SELECT 
      l.timestamp, 
      u.name AS user_name, 
      u.email AS user_email,
      l.type, 
      l.action, 
      l.details 
    FROM activity_logs l
    LEFT JOIN users u ON l.user_id = u.id
    ORDER BY l.timestamp DESC
    LIMIT 100
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results || []);
  });
});

// ---------- ADMIN REPORTS ----------
app.get('/admin-reports', (req, res) => {
  const reports = {};

  db.query('SELECT COUNT(*) as count FROM users', (err, result) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    reports.totalUsers = result[0]?.count || 0;

    db.query('SELECT COUNT(*) as count FROM smes WHERE status = 1', (err, result2) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      reports.totalSMEs = result2[0]?.count || 0;

      db.query('SELECT COUNT(*) as orders, COALESCE(SUM(total_price),0) as revenue FROM orders', (err, result3) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        reports.totalOrders = result3[0]?.orders || 0;
        reports.totalRevenue = Math.round(result3[0]?.revenue || 0);

        db.query(`SELECT DATE(created_at) as date, COUNT(*) as count 
                  FROM users WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                  GROUP BY DATE(created_at) ORDER BY date`, (err, rows) => {
          reports.userGrowth = (rows && rows.length) ? rows : [{ date: new Date().toISOString().split('T')[0], count: 0 }];

          db.query(`SELECT DATE(created_at) as date, COALESCE(SUM(total_price),0) as revenue 
                    FROM orders WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                    GROUP BY DATE(created_at) ORDER BY date`, (err, rows2) => {
            reports.revenueTrend = (rows2 && rows2.length) ? rows2 : [{ date: new Date().toISOString().split('T')[0], revenue: 0 }];

            db.query('SELECT category, COUNT(*) as count FROM smes WHERE status = 1 GROUP BY category LIMIT 10', (err, rows3) => {
              reports.topCategories = (rows3 && rows3.length) ? rows3 : [{ category: 'General', count: 1 }];

              db.query('SELECT status, COUNT(*) as count FROM orders GROUP BY status', (err, rows4) => {
                const statusObj = { Pending: 0, Paid: 0, Delivered: 0, Cancelled: 0 };
                if (rows4 && rows4.length) {
                  rows4.forEach(r => { statusObj[r.status] = r.count; });
                }
                reports.orderStatus = statusObj;
                res.json(reports);
              });
            });
          });
        });
      });
    });
  });
});

// SME REGISTRATION — NOW WITH 100% WORKING ACTIVITY LOG
app.post('/register-sme', (req, res) => {
  let { business_name, owner_name, owner_email, category, description } = req.body;

  // Get real logged-in user email (from frontend header) → fallback to body
  const currentUser = req.headers['x-user-email'] || owner_email;
  owner_email = currentUser || owner_email;

  if (!owner_email || !business_name || !owner_name || !category) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  owner_email = owner_email.toLowerCase().trim();

  db.query('SELECT * FROM smes WHERE owner_email = ?', [owner_email], (err, results) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    if (results.length > 0) {
      const sme = results[0];

      if (sme.status == 1) {
        return res.json({ message: 'Your business is already approved!' });
      }

      // UPDATE existing pending application
      db.query(
        `UPDATE smes SET business_name=?, owner_name=?, category=?, description=? WHERE owner_email=?`,
        [business_name, owner_name, category, description || '', owner_email],
        (err) => {
          if (err) return res.status(500).json({ message: 'Update failed' });

          // LOG THE UPDATE
          logActivity(
            null,
            owner_email,
            'SME Registration Updated',
            `"${business_name}" (${category}) — updated pending application`
          );

          res.json({ message: 'Updated! Waiting for approval.' });
        }
      );
    } else {
      // INSERT NEW APPLICATION
      db.query(
        'INSERT INTO smes (business_name, owner_name, owner_email, category, description, status) VALUES (?, ?, ?, ?, ?, 0)',
        [business_name, owner_name, owner_email, category, description || ''],
        (err, result) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Submit failed' });
          }

          // THIS LOG WILL SHOW UP BEAUTIFULLY IN YOUR ADMIN PANEL
          logActivity(
            null,
            owner_email,
            'SME Registration Submitted',
            `"${business_name}" by ${owner_name} (${owner_email}) | Category: ${category} | Status: Pending Approval`
          );

          res.json({ message: 'Business submitted for approval!' });
        }
      );
    }
  });
});

app.get('/my-business', (req, res) => {
  const { email } = req.query;
  if (!email) return res.json({});
  db.query('SELECT * FROM smes WHERE owner_email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({});
    res.json(results && results.length ? results[0] : {});
  });
});

app.post('/add-product-sme', upload.single('image'), (req, res) => {
  const { name, price, quantity, category, description, sme_email } = req.body;
  if (!sme_email) return res.status(400).json({ message: 'SME email required' });

  db.query('SELECT id FROM smes WHERE owner_email = ? AND status = 1', [sme_email], (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (!results || results.length === 0) {
      return res.json({ message: "Your business is not approved yet!" });
    }

    const sme_id = results[0].id;
    const image = req.file ? '/uploads/' + req.file.filename : '';

    db.query(
      'INSERT INTO products (name, price, quantity, category, description, image, sme_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, price, quantity, category, description, image, sme_id],
      (err) => {
        if (err) return res.status(500).json({ message: "Failed to add product" });
        res.json({ message: "Product added successfully!" });
      }
    );
  });
});

app.get('/my-products', (req, res) => {
  const { sme_email } = req.query;
  if (!sme_email) return res.status(400).json([]);
  const sql = `
    SELECT p.* FROM products p
    JOIN smes s ON p.sme_id = s.id
    WHERE s.owner_email = ?
  `;
  db.query(sql, [sme_email], (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results || []);
  });
});

// FIXED: SME only sees THEIR orders
app.get('/sme/my-orders', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const sql = `
    SELECT 
      o.id AS order_id,
      o.quantity,
      o.total_price,
      o.status,
      o.created_at AS order_date,
      o.mpesa_receipt,
      u.name AS customer_name,
      u.email AS customer_email,
      p.name AS product_name
    FROM orders o
    JOIN users u ON o.customer_id = u.id
    JOIN products p ON o.product_id = p.id
    JOIN smes s ON p.sme_id = s.id
    WHERE s.owner_email = ?
    ORDER BY o.created_at DESC
  `;

  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error('SME orders error:', err);
      return res.status(500).json([]);
    }
    res.json(results || []);
  });
});

app.post('/sme-login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, message: 'Email and password required' });

  db.query('SELECT u.*, s.status AS business_status FROM users u LEFT JOIN smes s ON u.email = s.owner_email WHERE u.email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });
    if (!results || results.length === 0) return res.json({ success: false, message: "User not found" });

    const user = results[0];
    if (password !== user.password) return res.json({ success: false, message: "Wrong password" });

    if (!user.business_status) return res.json({ success: false, message: "No business registered" });
    if (user.business_status != 1) return res.json({ success: false, message: "Business not approved yet" });

    res.json({
      success: true,
      user: { email: user.email, name: user.name, role: 'sme_owner' }
    });
  });
});

/// Replace your current /sme/ratings or /sme/reviews route with this
app.get('/sme/my-ratings', async (req, res) => {
  const smeId = req.user.sme_id || req.user.id;

  try {
    const { rows } = await pool.query(`
      WITH latest_ratings AS (
        SELECT DISTINCT ON (o.customer_id, p.id)
          r.*,
          p.name AS product_name,
          u.name AS customer_name,
          u.email AS customer_email
        FROM ratings r
        JOIN orders o ON r.order_id = o.id
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.customer_id = u.id
        WHERE p.sme_id = $1
        ORDER BY o.customer_id, p.id, r.created_at DESC
      )
      SELECT 
        product_name,
        customer_name,
        customer_email,
        stars,
        comment,
        created_at,
        ROUND(AVG(LENGTH(stars) - LENGTH(REPLACE(stars, '★', ''))) OVER (), 1) AS avg_rating,
        COUNT(*) OVER () AS total_reviews
      FROM latest_ratings
      ORDER BY created_at DESC
    `, [smeId]);

    res.json({
      average_rating: rows[0]?.avg_rating || 0,
      total_reviews: rows[0]?.total_reviews || 0,
      ratings: rows
    });

  } catch (err) {
    console.error(err);
    res.json({ average_rating: 0, total_reviews: 0, ratings: [] });
  }
});
// ========== ACTIVITY LOGS — 100% WORKING VERSION ==========
app.get('/activity-logs', (req, res) => {
  const sql = `
    SELECT 
      l.id,
      l.timestamp,
      l.action,
      l.details,
      COALESCE(u.name, u.email, 'System') AS user_name,
      u.email AS user_email
    FROM activity_logs l
    LEFT JOIN users u ON l.user_id = u.id
    ORDER BY l.timestamp DESC
    LIMIT 500
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Activity Logs DB Error:', err);
      return res.json([]);  // Still return empty array, no crash
    }
    res.json(results || []);
  });
});
// LOG ACTIVITY FUNCTION
function logActivity(userId, action, details = '') {
  db.query(
    'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
    [userId || null, action, details],
    (err) => { if (err) console.error('Log failed:', err); }
  );
}
// Add this route for approving SMEs
app.put('/sme-listings/:id/approve', (req, res) => {
  const id = req.params.id;
  db.query('UPDATE smes SET status = 1 WHERE id = ?', [id], (err, result) => {
    if (err || result.affectedRows === 0) {
      return res.status(500).json({ error: 'Failed to approve' });
    }
    // LOG THE ACTION
    logActivity(null, 'SME Approved', `Approved business ID: ${id}`);
    res.json({ success: true });
  });
});

app.put('/sme-listings/:id/reject', (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM smes WHERE id = ?', [id], () => {
    logActivity(null, 'SME Rejected', `Rejected business ID: ${id}`);
    res.json({ success: true });
  });
});

// AUTO-LOGGING FUNCTION
function logActivity(userId, action, details = '') {
  db.query(
    'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
    [userId || null, action, details]
  );
}

// APPROVE SME (with auto log)
app.put('/sme-listings/:id/approve', (req, res) => {
  const id = req.params.id;
  db.query('UPDATE smes SET status = 1 WHERE id = ?', [id], (err, result) => {
    if (err || result.affectedRows === 0) return res.status(500).json({ error: 'Failed' });
    logActivity(null, 'SME Approved', `Business ID: ${id}`);
    res.json({ success: true });
  });
});

// REJECT SME (with auto log)
app.put('/sme-listings/:id/reject', (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM smes WHERE id = ?', [id], () => {
    logActivity(null, 'SME Rejected', `Business ID: ${id}`);
    res.json({ success: true });
  });
});

// ========== AUTO-LOG EVERYTHING — ONE FUNCTION TO RULE THEM ALL ==========
function logActivity(userId, action, details = '') {
  const cleanDetails = details.substring(0, 500); // prevent too long text
  db.query(
    'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
    [userId || null, action, cleanDetails],
    (err) => { if (err) console.error('Log failed:', err); }
  );
}
// FINAL WORKING DELIVERED REPORT 
app.get('/admin-reports/delivered', (req, res) => {
  const sql = `
    SELECT 
      o.id AS order_id,
      o.total_price AS amount,
      o.mpesa_receipt AS receipt,
      o.quantity,
      o.created_at AS delivered_date,
      p.name AS product_name,
      COALESCE(u.name, 'Walk-in Customer') AS customer_name,
      COALESCE(s.business_name, 'Platform Sale') AS sme_name
    FROM orders o
    LEFT JOIN products p ON o.product_id = p.id
    LEFT JOIN users u ON o.customer_id = u.id
    LEFT JOIN smes s ON p.sme_id = s.id
    WHERE o.status = 'Delivered'
    ORDER BY o.created_at DESC
    LIMIT 100
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('DELIVERED REPORT ERROR:', err);
      return res.status(500).json({ error: err.sqlMessage || err.message });
    }
    res.json(results || []);
  });
});

// SUSPEND / UNSUSPEND USER
app.post('/suspend-user', (req, res) => {
  const { userId, action } = req.body;
  const newStatus = action === 'suspend' ? 'suspended' : 'active';

  db.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId], (err, result) => {
    if (err || result.affectedRows === 0) {
      return res.status(500).json({ message: 'Failed to update user' });
    }
    logActivity(null, 'User Suspended/Unsuspended', `User ID: ${userId} → ${newStatus}`);
    res.json({ message: `User ${newStatus === 'suspended' ? 'suspended' : 'unsuspended'} successfully` });
  });
});

// DELETE USER PERMANENTLY
app.delete('/delete-user/:id', (req, res) => {
  const userId = req.params.id;

  db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
    if (err || result.affectedRows === 0) {
      return res.status(500).json({ message: 'Failed to delete user' });
    }
    logActivity(null, 'User Deleted', `Permanently deleted user ID: ${userId}`);
    res.json({ message: 'User deleted permanently' });
  });
});

// ---------- START SERVER ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));