const express = require('express');
const app = express();
const port = 5000;
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();
const userRoute = require("./routes/user");
const authRoute = require("./routes/auth");
const productRoute = require("./routes/product");
const cartRoute = require("./routes/cart");
const orderRoute = require("./routes/order");
const stripeRoute = require("./routes/stripe");
const cors = require("cors");

//DB Connect
mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log(`MongoDB connected`);
  })
  .catch((err) => {
    console.log(err);
  });
// rest Api ROUTES
app.use(cors());
app.use(express.json());
app.use("/api/auth", authRoute);
app.use("/api/users", userRoute);
app.use("/api/products", productRoute);
app.use("/api/carts", cartRoute);
app.use("/api/orders", orderRoute);
app.use("/api/checkout", stripeRoute);


app.listen(process.env.port || 5000, () => {
  console.log(`Example app listening on port ${port}`)
})
