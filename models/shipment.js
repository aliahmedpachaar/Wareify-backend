// Filename: backend/models/Shipment.js

const mongoose = require('mongoose');

const historySchema = new mongoose.Schema({
    status: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    location: { type: String }
}, { _id: false });

const shipmentSchema = new mongoose.Schema({
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    itemName: { type: String, required: true },
    itemCategory: { type: String, required: true },
    quantity: { type: Number, required: true },
    recipient: { type: String, required: true },
    address: { type: String, required: true },
    status: { type: String, default: 'Pending' },
    rfidTag: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
    history: [historySchema]
});

module.exports = mongoose.model('Shipment', shipmentSchema);