
// blockchain.js
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const chainFile = path.join(__dirname, "chain.json");

class Block {
    /**
     * Represents a block in the blockchain.
     * @param {number} index - The block's position in the chain.
     * @param {string} timestamp - The ISO string timestamp of when the block was created.
     * @param {Array<Object>} data - An array of transactions (product data).
     * @param {string} previousHash - The hash of the previous block.
     */
    constructor(index, timestamp, data, previousHash = "") {
        this.index = index;
        this.timestamp = timestamp;
        this.data = data;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.miningTimeMs = 0; // FIX: To store how long mining took
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return crypto
            .createHash("sha256")
            .update(
                this.index + this.previousHash + this.timestamp + JSON.stringify(this.data) + this.nonce
            )
            .digest("hex");
    }

    mineBlock(difficulty) {
        const startTime = Date.now(); // FIX: Record start time
        while (this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0")) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
        const endTime = Date.now(); // FIX: Record end time
        this.miningTimeMs = endTime - startTime; // FIX: Store mining duration
        console.log(`Block Mined in ${this.miningTimeMs}ms. Hash: ${this.hash}`);
    }
}

class Blockchain {
    constructor() {
        this.difficulty = 4;
        this.chain = this.loadChainFromFile();
        this.pendingTransactions = []; 
    }

    loadChainFromFile() {
        if (fs.existsSync(chainFile)) {
            try {
                const raw = fs.readFileSync(chainFile);
                return JSON.parse(raw).map(obj => {
                    const block = new Block(obj.index, obj.timestamp, obj.data, obj.previousHash);
                    block.hash = obj.hash;
                    block.nonce = obj.nonce;
                    block.miningTimeMs = obj.miningTimeMs || 0;
                    return block;
                });
            } catch (error) {
                console.error("Error loading chain, creating a new one.", error);
            }
        }
        // FIX: Use an empty array for Genesis Block data for consistent handling
        const genesisBlock = new Block(0, "2025-01-01T00:00:00.000Z", [], "0");
        return [genesisBlock];
    }

    saveChainToFile() {
        fs.writeFileSync(chainFile, JSON.stringify(this.chain, null, 4));
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    minePendingTransactions() {
        // FIX: More robust check to prevent mining empty or invalid transaction pools
        if (!Array.isArray(this.pendingTransactions) || this.pendingTransactions.length === 0) {
            console.log("No valid pending transactions to mine.");
            return null;
        }
        
        const newBlock = new Block(
            this.chain.length,
            new Date().toISOString(),
            this.pendingTransactions,
            this.getLatestBlock().hash
        );

        newBlock.mineBlock(this.difficulty);

        console.log('Block successfully mined!');
        this.chain.push(newBlock);

        this.pendingTransactions = [];
        this.saveChainToFile();
        return newBlock;
    }

    /**
     * Adds a new transaction, enforcing a valid format.
     * @param {Object} transaction - The transaction (product data) to add.
     */
    addTransaction(transaction) {
        // FIX: Enforce that a transaction must have a productId
        if (!transaction || !transaction.productId) {
            console.error("Invalid transaction format. 'productId' is required.");
            return;
        }
        this.pendingTransactions.push(transaction);
        console.log(`Transaction for product ${transaction.productId} added to pending pool.`);
    }

    getChain() {
        return this.chain;
    }
    
    isChainValid() {
        for (let i = 1; i < this.chain.length; i++) {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (currentBlock.hash !== currentBlock.calculateHash()) {
                return false;
            }

            if (currentBlock.previousHash !== previousBlock.hash) {
                return false;
            }
            
            // FIX: Skip difficulty check for the Genesis block
            if (currentBlock.hash.substring(0, this.difficulty) !== Array(this.difficulty + 1).join("0")) {
                return false;
            }
        }
        return true;
    }

    findProductInBlockchain(productId) {
        for (const block of this.chain) {
            if (Array.isArray(block.data)) {
                for (const product of block.data) {
                    if (product.productId && product.productId === productId) {
                        return product;
                    }
                }
            }
        }
        return null;
    }
}

module.exports = new Blockchain();