const express = require('express');
const { exec } = require('child_process');
const mongoose = require('mongoose');

const app = express();
const port = 3000;
const mongoUrl = 'mongodb://localhost:27017';
let db;

// Middleware to parse JSON requests
app.use(express.json());

// Function to execute adb command and handle output
function runADBCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error executing command: ${error}`);
                reject(error);
            }
            if (stderr) {
                console.error(`Command had errors: ${stderr}`);
                reject(stderr);
            }
            resolve(stdout);
        });
    });
}

// Function to get device name or identifier
async function getDeviceName() {
    try {
        const command = 'adb shell getprop ro.product.model';
        const deviceName = await runADBCommand(command);
        return sanitizeDeviceName(deviceName.trim()); // Remove any extraneous whitespace
    } catch (err) {
        console.error('Error fetching device name:', err);
        throw err;
    }
}

// Function to sanitize device name for use in MongoDB
function sanitizeDeviceName(name) {
    // Remove or replace characters that are not allowed in MongoDB database names
    return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

// Function to connect to MongoDB with a specific database
async function connectToDB(dbName) {
    try {
        const mongoUrlWithDB = `${mongoUrl}/${dbName}`;
        await mongoose.connect(mongoUrlWithDB, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log(`Connected to MongoDB database: ${dbName}`);
    } catch (err) {
        console.error('Error connecting to MongoDB:', err);
        process.exit(1);
    }
}

// Define MongoDB Schemas and Models
function defineModels() {
    // Only define the models if they don't already exist
    if (mongoose.models.SMS) {
        global.SMS = mongoose.models.SMS;
    } else {
        const smsSchema = new mongoose.Schema({
            address: String,
            date: Number,
            type: Number,
            body: String
        }, { 
            timestamps: true,  // Add createdAt and updatedAt fields
            strict: false // Allow additional fields
        });
        global.SMS = mongoose.model('SMS', smsSchema);
    }

    if (mongoose.models.CallLog) {
        global.CallLog = mongoose.models.CallLog;
    } else {
        const callLogSchema = new mongoose.Schema({
            number: String,
            date: Number,
            duration: Number,
            type: Number
        }, { 
            timestamps: true,  // Add createdAt and updatedAt fields
            strict: false // Allow additional fields
        });
        global.CallLog = mongoose.model('CallLog', callLogSchema);
    }

    if (mongoose.models.Contact) {
        global.Contact = mongoose.models.Contact;
    } else {
        const contactSchema = new mongoose.Schema({
            display_name: String,
            number: String
        }, { 
            timestamps: true,  // Add createdAt and updatedAt fields
            strict: false // Allow additional fields
        });
        global.Contact = mongoose.model('Contact', contactSchema);
    }
}

// Parsing functions
function parseSMSData(data) {
    return data.split('\n').filter(line => line.trim()).map(line => {
        const obj = {};
        const parts = line.match(/(\w+)=([^,]+)/g);
        if (parts) {
            parts.forEach(part => {
                const [key, value] = part.split('=');
                // Exclude '_id' field to avoid validation issues
                if (key !== '_id') {
                    obj[key] = value === 'NULL' ? null : value;
                }
            });
        }
        return obj;
    }).filter(obj => obj.address); // Ensure we have valid SMS entries
}

function parseCallLogData(data) {
    return data.split('\n').filter(line => line.trim()).map(line => {
        const obj = {};
        const parts = line.match(/(\w+)=([^,]+)/g);
        if (parts) {
            parts.forEach(part => {
                const [key, value] = part.split('=');
                // Exclude '_id' field to avoid validation issues
                if (key !== '_id') {
                    obj[key] = value === 'NULL' ? null : value;
                }
            });
        }
        return obj;
    }).filter(obj => obj.number); // Ensure we have valid call log entries
}

function parseContactsData(data) {
    return data.split('\n').filter(line => line.trim()).map(line => {
        const obj = {};
        const parts = line.match(/(\w+)=([^,]+)/g);
        if (parts) {
            parts.forEach(part => {
                const [key, value] = part.split('=');
                // Exclude '_id' field to avoid validation issues
                if (key !== '_id') {
                    obj[key] = value === 'NULL' ? null : value;
                }
            });
        }
        return obj;
    }).filter(obj => obj.display_name); // Ensure we have valid contact entries
}

// Endpoint to query SMS messages and save to MongoDB
app.get('/sms', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);
        defineModels();

        const command = 'adb shell content query --uri content://sms/';
        const smsData = await runADBCommand(command);
        const parsedData = parseSMSData(smsData);

        await SMS.insertMany(parsedData);

        res.json(parsedData);
    } catch (err) {
        console.error('Error querying and saving SMS messages:', err);
        res.status(500).send('Error querying and saving SMS messages');
    }
});

// Endpoint to query call logs and save to MongoDB
app.get('/call-log', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);
        defineModels();

        const command = 'adb shell content query --uri content://call_log/calls/';
        const callLogData = await runADBCommand(command);
        const parsedData = parseCallLogData(callLogData);

        await CallLog.insertMany(parsedData);

        res.json(parsedData);
    } catch (err) {
        console.error('Error querying and saving call log:', err);
        res.status(500).send('Error querying and saving call log');
    }
});

// Endpoint to query contacts and save to MongoDB
app.get('/contacts', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);
        defineModels();

        const command = 'adb shell content query --uri content://contacts/phones/ --projection display_name:number';
        const contactsData = await runADBCommand(command);
        const parsedData = parseContactsData(contactsData);

        await Contact.insertMany(parsedData);

        res.json(parsedData);
    } catch (err) {
        console.error('Error querying and saving contacts:', err);
        res.status(500).send('Error querying and saving contacts');
    }
});

// Start the server
app.listen(port, async () => {
    console.log(`Server running on http://localhost:${port}`);
});
