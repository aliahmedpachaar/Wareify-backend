// models/Product.js
const mongoose = require("mongoose");

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  stock: { type: Number, required: true },
  description: { type: String }, // Make sure this field exists as per your form
  manufacturer: { type: String },
  manufacturedAt: { type: Date }, // Changed to Date type
  sellingLocation: { type: String },
  batchNo: { type: String },
  timestamp: { type: Date, default: Date.now }, // Changed to Date type, default to now
  image: { type: String, default: null },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Product", productSchema);