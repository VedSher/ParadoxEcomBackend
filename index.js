require('dotenv').config();
const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const { createProduct } = require('./controller/Product');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const paymentRouter = require('./routes/PaymentRoute'); // Import payment routes
const { User } = require('./model/User');
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');
const path = require('path');
const { Order } = require('./model/Order');
const { env } = require('process');

// Initialize Razorpay
const Razorpay = require('razorpay');
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Razorpay webhook handler
server.post(
  '/razorpay-webhook',
  express.raw({ type: 'application/json' }),
  async (request, response) => {
    const signature = request.headers['x-razorpay-signature'];

    try {
      // Verify webhook signature
      const shasum = crypto.createHmac('sha256', process.env.ENDPOINT_SECRET_);
      shasum.update(JSON.stringify(request.body));
      const digest = shasum.digest('hex');

      if (digest === signature) {
        // Extract event data
        const event = request.body;

        // Handle the event
        if (event.event === 'payment.authorized' || event.event === 'payment.captured') {
          const paymentId = event.payload.payment.entity.id;
          const orderId = event.payload.payment.entity.notes.orderId;
          
          // Update order status
          const order = await Order.findById(orderId);
          if (order) {
            order.paymentStatus = 'received';
            await order.save();
            console.log(`Payment received for order ${orderId}`);
          }
        }

        response.status(200).send('Webhook processed successfully');
      } else {
        response.status(400).send('Invalid signature');
      }
    } catch (err) {
      console.error('Webhook Error:', err.message);
      response.status(400).send(`Webhook Error: ${err.message}`);
    }
  }
);

// JWT options
const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = process.env.JWT_SECRET_KEY; 

// Middlewares
server.use(express.static(path.resolve(__dirname, 'build')));
server.use(cookieParser());
server.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  })
);
server.use(passport.authenticate('session'));
server.use(
  cors({
    exposedHeaders: ['X-Total-Count'],
  })
);
server.use(express.json()); // to parse req.body

// Routes
server.use('/products', isAuth(), productsRouter.router);
server.use('/categories', isAuth(), categoriesRouter.router);
server.use('/brands', isAuth(), brandsRouter.router);
server.use('/users', isAuth(), usersRouter.router);
server.use('/auth', authRouter.router);
server.use('/cart', isAuth(), cartRouter.router);
server.use('/orders', isAuth(), ordersRouter.router);
server.use('/payments', paymentRouter); // Use payment routes

// Fallback for React Router
server.get('*', (req, res) =>
  res.sendFile(path.resolve('build', 'index.html'))
);

// Passport Strategies
passport.use(
  'local',
  new LocalStrategy({ usernameField: 'email' }, async function (
    email,
    password,
    done
  ) {
    // by default passport uses username
    console.log({ email, password });
    try {
      const user = await User.findOne({ email: email });
      console.log(email, password, user);
      if (!user) {
        return done(null, false, { message: 'invalid credentials' }); // for safety
      }
      crypto.pbkdf2(
        password,
        user.salt,
        310000,
        32,
        'sha256',
        async function (err, hashedPassword) {
          if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
            return done(null, false, { message: 'invalid credentials' });
          }
          const token = jwt.sign(
            sanitizeUser(user),
            process.env.JWT_SECRET_KEY
          );
          done(null, { id: user.id, role: user.role, token }); // this lines sends to serializer
        }
      );
    } catch (err) {
      done(err);
    }
  })
);

passport.use(
  'jwt',
  new JwtStrategy(opts, async function (jwt_payload, done) {
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, sanitizeUser(user)); // this calls serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

// Serialize and Deserialize User
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, { id: user.id, role: user.role });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// Start the server
main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect(process.env.MONGODB_URL);
  console.log('Database connected');
}

server.listen(process.env.PORT, () => {
  console.log('Server started');
});