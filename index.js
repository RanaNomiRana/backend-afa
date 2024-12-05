const express = require('express');
const { exec } = require('child_process');
const mongoose = require('mongoose');
const moment = require('moment');
const natural = require('natural');
const cors = require('cors');
const path = require('path');
const { spawn } = require('child_process');


const Sentiment = require('sentiment');

const app = express();
const port = 3000;
const mongoUrl = 'mongodb://localhost:27017';

app.use(express.json());
app.use(cors());

const sentiment = new Sentiment();

function runADBCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error executing command: ${error}`);
                return reject(error);
            }
            if (stderr) {
                console.error(`Command had errors: ${stderr}`);
                return reject(stderr);
            }
            resolve(stdout);
        });
    });
}

async function getDeviceName() {
    try {
        const command = 'adb shell getprop ro.product.model';
        const deviceName = await runADBCommand(command);
        return sanitizeDeviceName(deviceName.trim());
    } catch (err) {
        console.error('Error fetching device name:', err);
        throw err;
    }
}

function sanitizeDeviceName(name) {
    return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

async function connectToDB(dbName) {
    try {
        const mongoUrlWithDB = `${mongoUrl}/${dbName}`;
        await mongoose.connect(mongoUrlWithDB, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log(`Connected to MongoDB database: ${dbName}`);

       
    } catch (err) {
        console.error('Error connecting to MongoDB:', err);
        process.exit(1);
    }
}

const smsSchema = new mongoose.Schema({
    address: String,
    date: String,
    type: String,
    body: String,
    isSuspicious: Boolean,
    category: String
}, { timestamps: true, strict: false });

const callLogSchema = new mongoose.Schema({
    number: String,
    date: String,
    duration: String,
    type: String
}, { timestamps: true, strict: false });

const contactSchema = new mongoose.Schema({
    display_name: String,
    number: String
}, { timestamps: true, strict: false });


// Define the schema for ConnectionDetail
const connectionDetailSchema = new mongoose.Schema({
    deviceName: {
        type: String,
        required: true,
    },
    connectorId: {
        type: String,
        required: true,
    },
    additionalInfo: {
        type: String,
        required: false, // Set to true if this field should be required
    },
    investigatorId: {
        type: String,
        required: true,
    },
}, {
    timestamps: true, // Adds createdAt and updatedAt fields
});

const reportSchema = new mongoose.Schema({
    caseNumber: { type: String, required: true },
    remark: { type: String, required: true },
    deviceName: { type: String, required: true },
    sms: {
      totalMessages: { type: Number, required: true },
      suspiciousMessages: { type: Number, required: true },
      fraudMessages: { type: Number, required: true },
      criminalMessages: { type: Number, required: true },
      cyberbullyingMessages: { type: Number, required: true },
      threatMessages: { type: Number, required: true },
      negativeSentimentMessages: { type: Number, required: true },
    },
    calls: {
      totalCalls: { type: Number, required: true },
      incomingCalls: { type: Number, required: true },
      outgoingCalls: { type: Number, required: true },
      missedCalls: { type: Number, required: true },
    },
    contacts: {
      totalContacts: { type: Number, required: true },
    },
    createdAt: { type: Date, default: Date.now },
  });
  
  // Create the model for reports

const timelineAnalysisSchema = new mongoose.Schema({
    date: { type: String, required: true }, // Format: YYYY-MM-DD
    totalMessages: { type: Number, default: 0 },
    suspiciousMessages: { type: Number, default: 0 },
    totalCalls: { type: Number, default: 0 },
    incomingCalls: { type: Number, default: 0 },
    outgoingCalls: { type: Number, default: 0 },
    missedCalls: { type: Number, default: 0 },
}, { timestamps: true });



const spamURLAnalysisSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    date: { type: Date, required: true },
    body: { type: String, required: true }
}, { timestamps: true });

const fileSchema = new mongoose.Schema({
    fileName: String,
    filePath: String,
    createdAt: { type: Date, default: Date.now }
  });
  
  const File = mongoose.model('File', fileSchema);
  
  
  // Define the DataCorrelation schema
  const dataCorrelationSchema = new mongoose.Schema({
    number: { type: String, required: true },
    smsCount: { type: Number, required: true },
    callLogs: [callLogSchema] // Array of CallLog sub-documents
  }, { timestamps: true }); // Optional: add timestamps for createdAt and updatedAt
  
  // Create and export the DataCorrelation model
  const DataCorrelation = mongoose.model('DataCorrelation', dataCorrelationSchema);
  
const SpamURLAnalysis = mongoose.model('SpamURLAnalysis', spamURLAnalysisSchema);


const TimelineAnalysis = mongoose.model('TimelineAnalysis', timelineAnalysisSchema);

const Report = mongoose.model('Report', reportSchema);





// Create the model from the schema
const ConnectionDetail = mongoose.model('ConnectionDetail', connectionDetailSchema);

const SMS = mongoose.models.SMS || mongoose.model('SMS', smsSchema);
const CallLog = mongoose.models.CallLog || mongoose.model('CallLog', callLogSchema);
const Contact = mongoose.models.Contact || mongoose.model('Contact', contactSchema);

smsSchema.index({ address: 1 });
callLogSchema.index({ number: 1 });

const fraudKeywords = [
    'fraud', 'scam', 'money laundering', 'tax evasion', 'illegal transaction',
    'advance fee', 'phishing', 'investment scheme', 'fake lottery', 'unclaimed prize',
    'giveaway', 'credit card fraud', 'identity theft', 'wire transfer', 'account verification',
    'personal information', 'confidentiality', 'guaranteed win', 'earn money fast', 'risk-free'
];

const fraudPatterns = /buy now|limited time offer|guaranteed|risk-free|call now|exclusive deal|free gift|act now|urgent|cash prize/i;

const criminalKeywords = [
    'crime', 'theft', 'robbery', 'murder', 'assault', 'terrorism', 'drug trafficking',
    'illegal possession', 'kidnapping', 'extortion', 'arson', 'stolen goods', 'gang violence',
    'underworld', 'mafia', 'hitman', 'warrant', 'crime scene', 'criminal record', 
    'dakati', 'qatal', 'dhoka', 'bomb', 'explosive', 'attack', 'violence', 'assassin'
];

const criminalPatterns = /criminal|felony|law enforcement|arrest|warrant|wanted|gang|drug deal|illegal|offender|explosive|attack|violence/i;

const cyberbullyingKeywords = [
    'bully', 'harass', 'threaten', 'abuse', 'victim', 'cyberstalk', 'intimidate',
    'insult', 'demean', 'humiliate', 'shame', 'mock', 'belittle', 'coerce', 'blackmail',
    'derogatory', 'malicious', 'discriminate', 'targeted attack', 'online harassment'
];

const cyberbullyingPatterns = /bully|harassment|intimidation|abuse|stalker|humiliate|shame|mock|insult|derogatory/i;

const threatKeywords = [
    'explosive', 'bomb', 'attack', 'threat', 'danger', 'hazard', 'weapon', 
    'assassinate', 'kidnap', 'hostage', 'terror', 'risk', 'emergency', 
    'unsafe', 'explosive device', 'chemical weapon', 'biological weapon'
];

const threatPatterns = /bomb|explosive|attack|danger|threat|risk|terror|unsafe/i;

function parseData(data, fields) {
    return data.split('\n').filter(line => line.trim()).map(line => {
        const obj = {};
        const parts = line.match(/(\w+)=([^,]+)/g);
        if (parts) {
            parts.forEach(part => {
                const [key, value] = part.split('=');
                if (fields.includes(key)) {
                    obj[key] = value === 'NULL' ? null : value;
                }
            });
        }
        return obj;
    });
}

function detectFraudulentLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());
    
    return fraudKeywords.some(keyword => words.includes(keyword)) || fraudPatterns.test(text);
}

function detectCriminalLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());

    return criminalKeywords.some(keyword => words.includes(keyword)) || criminalPatterns.test(text);
}

function detectCyberbullyingLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());

    return cyberbullyingKeywords.some(keyword => words.includes(keyword)) || cyberbullyingPatterns.test(text);
}

function detectThreatLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());

    return threatKeywords.some(keyword => words.includes(keyword)) || threatPatterns.test(text);
}



// Define a function to get an emoji based on the sentiment score
function getSentimentEmoji(score) {
    if (score < -2) {
        return '😡'; // Angry or very negative sentiment
    } else if (score < 0) {
        return '😞'; // Sad or negative sentiment
    } else if (score === 0) {
        return '😐'; // Neutral sentiment
    } else if (score <= 2) {
        return '😊'; // Happy or positive sentiment
    } else {
        return '😁'; // Very happy or extremely positive sentiment
    }
}

// Update the analyzeSentiment function to include emojis
function analyzeSentiment(text) {
    const result = sentiment.analyze(text); 
    return {
        isNegative: result.score < -2, // Arbitrary threshold for negative sentiment
        emoji: getSentimentEmoji(result.score)
    };
}

function parseSMSData(data) {
    return parseData(data, ['address', 'date', 'type', 'body']).map(item => {
        if (item.type) {
            item.type = item.type === '1' ? 'received' : 'sent';
        }
        if (item.date) {
            item.date = moment(parseInt(item.date, 10)).format('YYYY-MM-DD HH:mm:ss');
        }
        if (item.body) {
            const sentimentAnalysis = analyzeSentiment(item.body);
            const isSuspicious = detectFraudulentLanguage(item.body) || 
                                 detectCriminalLanguage(item.body) || 
                                 detectCyberbullyingLanguage(item.body) || 
                                 detectThreatLanguage(item.body) || 
                                 sentimentAnalysis.isNegative;
            item.isSuspicious = isSuspicious;
            item.sentimentEmoji = sentimentAnalysis.emoji; // Add sentiment emoji

            if (isSuspicious) {
                if (detectFraudulentLanguage(item.body)) {
                    item.category = 'fraud';
                } else if (detectCriminalLanguage(item.body)) {
                    item.category = 'criminal';
                } else if (detectCyberbullyingLanguage(item.body)) {
                    item.category = 'cyberbullying';
                } else if (detectThreatLanguage(item.body)) {
                    item.category = 'threat';
                } else if (sentimentAnalysis.isNegative) {
                    item.category = 'negative_sentiment';
                }
            } else {
                item.category = 'normal';
            }
        }
        return item;
    });
}

app.get('/sms', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        // Fetch received SMS
        const receivedSmsCommand = 'adb shell content query --uri content://sms/inbox';
        const receivedSmsData = await runADBCommand(receivedSmsCommand);
        const parsedReceivedSmsData = parseSMSData(receivedSmsData);

        // Fetch sent SMS
        const sentSmsCommand = 'adb shell content query --uri content://sms/sent';
        const sentSmsData = await runADBCommand(sentSmsCommand);
        const parsedSentSmsData = parseSMSData(sentSmsData);

        // Combine received and sent SMS data
        const allSmsData = [...parsedReceivedSmsData, ...parsedSentSmsData];

        // Fetch contacts data
        const contacts = await Contact.find({}).exec();
        const contactsMap = new Map(contacts.map(contact => [contact.number, contact.display_name]));

        // Update SMS data with contact names and categories
        const updatedSmsData = allSmsData.map(sms => {
            if (contactsMap.has(sms.address)) {
                sms.contactName = contactsMap.get(sms.address);
            } else {
                sms.contactName = null; // or any other value if the contact name is not found
            }
            if (sms.body) {
                const sentimentAnalysis = analyzeSentiment(sms.body);
                sms.isSuspicious = detectFraudulentLanguage(sms.body) || 
                                   detectCriminalLanguage(sms.body) || 
                                   detectCyberbullyingLanguage(sms.body) || 
                                   detectThreatLanguage(sms.body) || 
                                   sentimentAnalysis.isNegative;
                sms.sentimentEmoji = sentimentAnalysis.emoji; // Add sentiment emoji

                if (sms.isSuspicious) {
                    if (detectFraudulentLanguage(sms.body)) {
                        sms.category = 'fraud';
                    } else if (detectCriminalLanguage(sms.body)) {
                        sms.category = 'criminal';
                    } else if (detectCyberbullyingLanguage(sms.body)) {
                        sms.category = 'cyberbullying';
                    } else if (detectThreatLanguage(sms.body)) {
                        sms.category = 'threat';
                    } else if (sentimentAnalysis.isNegative) {
                        sms.category = 'negative_sentiment';
                    }
                } else {
                    sms.category = 'normal';
                }
            }
            return sms;
        });

        // Clear existing SMS data before inserting new
        await SMS.deleteMany({});
        
        // Store new SMS data
        await SMS.insertMany(updatedSmsData);

        // Respond with updated SMS data
        res.json(updatedSmsData);
    } catch (err) {
        console.error('Error querying and saving SMS data:', err);
        res.status(500).send('Error querying and saving SMS data');
    }
});



app.post('/extract', (req, res) => {
    // Get the directory (optional) from the request body
    const { directory } = req.body;

    // Define the root directory of the SD card, which will be used to pull all the files
    const sdCardPath = '/sdcard/';

    // If a directory is provided, append it to the SD card path

    // ADB command to pull the entire SD card data (or specific directory if provided)
    const adbCommand = `adb pull ${sdCardPath} ./${directory}/`;

    exec(adbCommand, (error, stdout, stderr) => {
        if (error || stderr) {
            return res.status(500).send({
                success: false,
                message: 'Failed to extract data from SD card',
                error: error || stderr
            });
        }

        // Once the files are pulled, now we save them to the database
        const extractedDirPath = path.resolve(`./${directory}`);

        // Ensure the extracted folder exists
        if (!fs.existsSync(extractedDirPath)) {
            return res.status(500).send({
                success: false,
                message: 'No files extracted. Check if the pull command worked.'
            });
        }

        // Read the files from the extracted folder and save their info to the database
        const files = fs.readdirSync(extractedDirPath);

        if (files.length === 0) {
            return res.status(500).send({
                success: false,
                message: 'No files found after extraction.'
            });
        }

        // Iterate over each file in the directory
        const fileSavePromises = files.map(file => {
            const filePath = path.join(extractedDirPath, file);

            // Only save files (ignore directories)
            if (fs.statSync(filePath).isFile()) {
                const newFile = new File({
                    fileName: file,
                    filePath: filePath
                });

                return newFile.save()
                    .then(() => console.log(`Saved file: ${file}`))
                    .catch(err => console.log(`Error saving file: ${file}`, err));
            }
        });

        // Wait for all files to be saved to the database
        Promise.all(fileSavePromises)
            .then(() => {
                res.send({
                    success: true,
                    message: 'Data successfully extracted and saved to database'
                });
            })
            .catch(err => {
                res.status(500).send({
                    success: false,
                    message: 'Error saving files to the database',
                    error: err
                });
            });
    });
});
  
 

// Assuming you are using Express and have a model ConnectionDetail


app.get('/connection-details', async (req, res) => {
    try {
        // Retrieve all documents from the ConnectionDetail collection
        const connectionDetails = await ConnectionDetail.find();

        res.status(200).json(connectionDetails);
    } catch (err) {
        console.error('Error retrieving additional information:', err);
        res.status(500).send('Error retrieving additional information');
    }
});

app.get('/whatsapp/chats', async (req, res) => {
    try {
        const command = 'adb shell am start -n com.whatsapp/.Main';
        await runADBCommand(command);

        const getMessagesCommand = 'adb shell content query --uri content://sms'; // Adjust command for WhatsApp
        const result = await runADBCommand(getMessagesCommand);
        res.json({ messages: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

function formatDuration(seconds) {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
}

function parseCallLogData(data) {
    return parseData(data, ['number', 'date', 'duration', 'type']).map(item => {
        if (item.type) {
            switch (item.type) {
                case '1':
                    item.type = 'incoming';
                    break;
                case '2':
                    item.type = 'outgoing';
                    break;
                case '3':
                    item.type = 'missed';
                    break;
                default:
                    item.type = 'unknown';
                    break;
            }
        }
        if (item.date) {
            item.date = moment(parseInt(item.date, 10)).format('YYYY-MM-DD HH:mm:ss');
        }
        if (item.duration) {
            item.duration = formatDuration(parseInt(item.duration, 10));
        }
        return item;
    });
}

function parseContactsData(data) {
    return parseData(data, ['display_name', 'number']);
}

app.get('/device-name', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        res.json({ deviceName });
    } catch (err) {
        console.error('Error fetching device name:', err);
        res.status(500).send('Error fetching device name');
    }
});




app.get('/sms-stats', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        // Aggregate SMS data to count total SMS by number/address
        const smsStats = await SMS.aggregate([
            {
                $group: {
                    _id: "$address",
                    totalMessages: { $sum: 1 }
                }
            },
            {
                $sort: { totalMessages: -1 } // Sort by totalMessages in descending order
            }
        ]).exec();

        res.json(smsStats);
    } catch (err) {
        console.error('Error aggregating SMS data:', err);
        res.status(500).send('Error aggregating SMS data');
    }
});

app.get('/call-log', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const callLogCommand = 'adb';
        const callLogArgs = ['shell', 'content', 'query', '--uri', 'content://call_log/calls'];

        const adbProcess = spawn(callLogCommand, callLogArgs);

        let callLogData = '';

        adbProcess.stdout.on('data', (data) => {
            callLogData += data.toString();
        });

        adbProcess.stderr.on('data', (data) => {
            console.error('stderr:', data.toString());
        });

        adbProcess.on('close', async (code) => {
            if (code !== 0) {
                console.error(`adb process exited with code ${code}`);
                return res.status(500).send('Error querying call log');
            }

            const parsedCallLogData = parseCallLogData(callLogData);

            await CallLog.deleteMany({});
            await CallLog.insertMany(parsedCallLogData);

            res.json(parsedCallLogData);
        });
    } catch (err) {
        console.error('Error querying and saving call log data:', err);
        res.status(500).send('Error querying and saving call log data');
    }
});

app.get('/contacts', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const contactsCommand = 'adb shell content query --uri content://contacts/phones/';
        const contactsData = await runADBCommand(contactsCommand);
        const parsedContactsData = parseContactsData(contactsData);

        await Contact.deleteMany({});
        await Contact.insertMany(parsedContactsData);

        res.json(parsedContactsData);
    } catch (err) {
        console.error('Error querying and saving contacts data:', err);
        res.status(500).send('Error querying and saving contacts data');
    }
});


app.get('/comprehensive-report', async (req, res) => {
    try {
        // Step 1: Get the device name
        const deviceName = await getDeviceName();
        const dbName = sanitizeDeviceName(deviceName);

        // Step 2: Connect to the appropriate MongoDB database
        await connectToDB(dbName);

        // Step 3: Fetch SMS data
        const smsData = await SMS.find().sort({ date: -1 }).exec();

        // Step 4: Fetch call logs
        const callLogs = await CallLog.find().sort({ date: -1 }).exec();

        // Step 5: Fetch contacts
        const contacts = await Contact.find().exec();

        // Step 6: Aggregate SMS statistics
        const smsStats = await SMS.aggregate([
            {
                $group: {
                    _id: null,
                    totalMessages: { $sum: 1 },
                    suspiciousMessages: { $sum: { $cond: ['$isSuspicious', 1, 0] } },
                    fraud: { $sum: { $cond: [{ $eq: ['$category', 'fraud'] }, 1, 0] } },
                    criminal: { $sum: { $cond: [{ $eq: ['$category', 'criminal'] }, 1, 0] } },
                    cyberbullying: { $sum: { $cond: [{ $eq: ['$category', 'cyberbullying'] }, 1, 0] } },
                    threat: { $sum: { $cond: [{ $eq: ['$category', 'threat'] }, 1, 0] } },
                    negative_sentiment: { $sum: { $cond: [{ $eq: ['$category', 'negative_sentiment'] }, 1, 0] } }
                }
            }
        ]).exec();

        // Step 7: Aggregate call statistics
        const callStats = await CallLog.aggregate([
            {
                $group: {  
                    _id: null,
                    totalCalls: { $sum: 1 },
                    incomingCalls: { $sum: { $cond: [{ $eq: ['$type', 'incoming'] }, 1, 0] } },
                    outgoingCalls: { $sum: { $cond: [{ $eq: ['$type', 'outgoing'] }, 1, 0] } },
                    missedCalls: { $sum: { $cond: [{ $eq: ['$type', 'missed'] }, 1, 0] } }
                }
            }
        ]).exec();

        // Step 8: Perform timeline analysis for SMS
        const smsTimeline = await SMS.aggregate([
            {
                $addFields: {
                    date: {
                        $dateFromString: { dateString: "$date" }
                    }
                }
            },
            {
                $match: {
                    date: { $gte: new Date('2024-01-01T00:00:00Z'), $lte: new Date() }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$date" },
                        month: { $month: "$date" },
                        day: { $dayOfMonth: "$date" }
                    },
                    totalMessages: { $sum: 1 },
                    suspiciousMessages: { $sum: { $cond: [{ $eq: ["$isSuspicious", true] }, 1, 0] } }
                }
            },
            {
                $addFields: {
                    date: {
                        $dateFromParts: {
                            year: "$_id.year",
                            month: "$_id.month",
                            day: "$_id.day"
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$date" } },
                    totalMessages: 1,
                    suspiciousMessages: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        // Step 9: Perform timeline analysis for calls
        const callTimeline = await CallLog.aggregate([
            {
                $addFields: {
                    date: {
                        $dateFromString: { dateString: "$date" }
                    }
                }
            },
            {
                $match: {
                    date: { $gte: new Date('2024-01-01T00:00:00Z'), $lte: new Date() }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$date" },
                        month: { $month: "$date" },
                        day: { $dayOfMonth: "$date" }
                    },
                    totalCalls: { $sum: 1 },
                    incomingCalls: { $sum: { $cond: [{ $eq: ["$type", "incoming"] }, 1, 0] } },
                    outgoingCalls: { $sum: { $cond: [{ $eq: ["$type", "outgoing"] }, 1, 0] } },
                    missedCalls: { $sum: { $cond: [{ $eq: ["$type", "missed"] }, 1, 0] } }
                }
            },
            {
                $addFields: {
                    date: {
                        $dateFromParts: {
                            year: "$_id.year",
                            month: "$_id.month",
                            day: "$_id.day"
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$date" } },
                    totalCalls: 1,
                    incomingCalls: 1,
                    outgoingCalls: 1,
                    missedCalls: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        // Step 10: Perform URL analysis
        const smsWithUrls = await SMS.find({ body: /http:\/\/|https:\/\/|www\./i }).exec();

        // Step 11: Perform data correlation
        const dataCorrelation = await SMS.aggregate([
            { $group: { _id: "$address", smsCount: { $sum: 1 } } },
            { $sort: { smsCount: -1 } },
            { $limit: 10 }
        ]).exec();

        const correlatedNumbersPromises = dataCorrelation.map(async (sms) => {
            try {
                const callLogs = await CallLog.find({ number: sms._id });
                return {
                    number: sms._id,
                    smsCount: sms.smsCount,
                    callLogs
                };
            } catch (error) {
                console.error(`Error fetching call logs for number ${sms._id}:`, error);
                return {
                    number: sms._id,
                    smsCount: sms.smsCount,
                    callLogs: []
                };
            }
        });

        const dataCorrelationResults = await Promise.all(correlatedNumbersPromises);

        // Combine SMS and Call Log timeline data
        const combinedTimeline = [];

        const allDates = new Set([
            ...smsTimeline.map(entry => entry.date),
            ...callTimeline.map(entry => entry.date)
        ]);

        allDates.forEach(date => {
            const smsEntry = smsTimeline.find(entry => entry.date === date) || {};
            const callEntry = callTimeline.find(entry => entry.date === date) || {};

            combinedTimeline.push({
                date,
                totalMessages: smsEntry.totalMessages || 0,
                suspiciousMessages: smsEntry.suspiciousMessages || 0,
                totalCalls: callEntry.totalCalls || 0,
                incomingCalls: callEntry.incomingCalls || 0,
                outgoingCalls: callEntry.outgoingCalls || 0,
                missedCalls: callEntry.missedCalls || 0
            });
        });

        combinedTimeline.sort((a, b) => new Date(a.date) - new Date(b.date));

        // Step 12: Respond with the comprehensive report
        res.json({
            deviceName,
            smsData,
            callLogs,
            contacts,
            smsStats: smsStats[0] || {},
            callStats: callStats[0] || {},
            timelineAnalysis: combinedTimeline,
            smsWithUrls,
            dataCorrelationResults
        });
    } catch (err) {
        console.error('Error generating comprehensive report:', err);
        res.status(500).json({ error: 'Failed to generate comprehensive report' });
    }
});


app.get('/short-report', async (req, res) => {
    try {
        // Step 1: Get the device name and sanitize
        const deviceName = await getDeviceName();
        const dbName = sanitizeDeviceName(deviceName);

        // Step 2: Connect to the appropriate MongoDB database
        await connectToDB(dbName);

        // Step 3: Count SMS messages
        const totalSMSCount = await SMS.countDocuments().exec();
        const suspiciousSMSCount = await SMS.countDocuments({ isSuspicious: true }).exec();
        const fraudSMSCount = await SMS.countDocuments({ category: 'fraud' }).exec();
        const criminalSMSCount = await SMS.countDocuments({ category: 'criminal' }).exec();
        const cyberbullyingSMSCount = await SMS.countDocuments({ category: 'cyberbullying' }).exec();
        const threatSMSCount = await SMS.countDocuments({ category: 'threat' }).exec();
        const negativeSentimentSMSCount = await SMS.countDocuments({ category: 'negative_sentiment' }).exec();

        // Step 4: Count Call logs
        const totalCallsCount = await CallLog.countDocuments().exec();
        const incomingCallsCount = await CallLog.countDocuments({ type: 'incoming' }).exec();
        const outgoingCallsCount = await CallLog.countDocuments({ type: 'outgoing' }).exec();
        const missedCallsCount = await CallLog.countDocuments({ type: 'missed' }).exec();

        // Step 5: Count Contacts
        const totalContactsCount = await Contact.countDocuments().exec();

        // Step 6: Fetch the timeline analysis data
        const timelineData = await TimelineAnalysis.find().exec();
        if (!timelineData || timelineData.length === 0) {
            console.warn('No timeline analysis data found.');
        }

        // Step 7: Fetch Data Correlation
        const dataCorrelation = await DataCorrelation.find().exec();
        if (!dataCorrelation || dataCorrelation.length === 0) {
            console.warn('No data correlation found.');
        }

      

       

        // Step 10: Create the short report data
        const reportData = {
            deviceName,
            sms: {
                totalMessages: totalSMSCount,
                suspiciousMessages: suspiciousSMSCount,
                fraudMessages: fraudSMSCount,
                criminalMessages: criminalSMSCount,
                cyberbullyingMessages: cyberbullyingSMSCount,
                threatMessages: threatSMSCount,
                negativeSentimentMessages: negativeSentimentSMSCount,
            },
            calls: {
                totalCalls: totalCallsCount,
                incomingCalls: incomingCallsCount,
                outgoingCalls: outgoingCallsCount,
                missedCalls: missedCallsCount,
            },
            contacts: {
                totalContacts: totalContactsCount,
            },
        };

        // Step 11: Send the short report as JSON response
        res.json(reportData);

    } catch (err) {
        console.error('Error generating short report:', err);
        res.status(500).json({ error: 'Failed to generate short report' });
    }
});





app.post('/short-report', async (req,  res) => {
    try {
        const { caseNumber, remark } = req.body;

        // Validate inputs
        if (!caseNumber || !remark) {
            return res.status(400).json({ error: 'Case number and remark are required' });
        }

        // Step 1: Get the device name and sanitize it
        const deviceName = await getDeviceName();
        const dbName = sanitizeDeviceName(deviceName);

        // Step 2: Connect to the appropriate MongoDB database
        await connectToDB(dbName);

        // Step 3: Count SMS messages
        const totalSMSCount = await SMS.countDocuments().exec();
        const suspiciousSMSCount = await SMS.countDocuments({ isSuspicious: true }).exec();
        const fraudSMSCount = await SMS.countDocuments({ category: 'fraud' }).exec();
        const criminalSMSCount = await SMS.countDocuments({ category: 'criminal' }).exec();
        const cyberbullyingSMSCount = await SMS.countDocuments({ category: 'cyberbullying' }).exec();
        const threatSMSCount = await SMS.countDocuments({ category: 'threat' }).exec();
        const negativeSentimentSMSCount = await SMS.countDocuments({ category: 'negative_sentiment' }).exec();

        // Step 4: Count Call logs
        const totalCallsCount = await CallLog.countDocuments().exec();
        const incomingCallsCount = await CallLog.countDocuments({ type: 'incoming' }).exec();
        const outgoingCallsCount = await CallLog.countDocuments({ type: 'outgoing' }).exec();
        const missedCallsCount = await CallLog.countDocuments({ type: 'missed' }).exec();

        // Step 5: Count Contacts
        const totalContactsCount = await Contact.countDocuments().exec();

        // Step 6: Create the short report data
        const reportData = {
            caseNumber,
            remark,
            deviceName,
            sms: {
                totalMessages: totalSMSCount,
                suspiciousMessages: suspiciousSMSCount,
                fraudMessages: fraudSMSCount,
                criminalMessages: criminalSMSCount,
                cyberbullyingMessages: cyberbullyingSMSCount,
                threatMessages: threatSMSCount,
                negativeSentimentMessages: negativeSentimentSMSCount,
            },
            calls: {
                totalCalls: totalCallsCount,
                incomingCalls: incomingCallsCount,
                outgoingCalls: outgoingCallsCount,
                missedCalls: missedCallsCount,
            },
            contacts: {
                totalContacts: totalContactsCount,
            }
        };

        // Step 7: Save the report data to the database
        const newReport = new Report(reportData);
        await newReport.save();

        // Step 8: Respond with success message and the saved report
        res.status(201).json({
            message: 'Report saved successfully',
            report: newReport
        });

    } catch (err) {
        console.error('Error generating short report:', err);
        res.status(500).json({ error: 'Failed to generate short report' });
    }
});


app.get('/search', async (req, res) => {
    const { keyword } = req.query;

    if (!keyword) {
        return res.status(400).send('Keyword is required');
    }

    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const smsResults = await SMS.find({
            $or: [
                { body: new RegExp(keyword, 'i') },
                { address: new RegExp(keyword, 'i') }
            ]
        }).exec().then(sms => sms.map(item => ({
            ...item.toObject(),
            isSuspicious: detectFraudulentLanguage(item.body) || 
                          detectCriminalLanguage(item.body) || 
                          detectCyberbullyingLanguage(item.body) || 
                          detectThreatLanguage(item.body) || 
                          analyzeSentiment(item.body)
        })));

        const callLogResults = await CallLog.find({
            $or: [
                { number: new RegExp(keyword, 'i') }
            ]
        });

        const contactResults = await Contact.find({
            $or: [
                { display_name: new RegExp(keyword, 'i') },
                { number: new RegExp(keyword, 'i') }
            ]
        });

        res.json({
            sms: smsResults,
            callLog: callLogResults,
            contacts: contactResults
        });
    } catch (err) {
        console.error('Error searching data:', err);
        res.status(500).send('Error searching data');
    }
});
 
app.get('/timeline-analysis', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        // Aggregate SMS data
        const smsData = await SMS.aggregate([
            {
                $addFields: {
                    date: {
                        $dateFromString: { dateString: "$date" }
                    }
                }
            },
            {
                $match: {
                    date: { $gte: new Date('2024-01-01T00:00:00Z'), $lte: new Date() }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$date" },
                        month: { $month: "$date" },
                        day: { $dayOfMonth: "$date" }
                    },
                    details: { $push: { address: "$address", body: "$body", contactName: "$contactName", category: "$category", isSuspicious: "$isSuspicious", sentimentEmoji: "$sentimentEmoji" } },
                    totalMessages: { $sum: 1 },
                    suspiciousMessages: { $sum: { $cond: [{ $eq: ["$isSuspicious", true] }, 1, 0] } }
                }
            },
            {
                $addFields: {
                    date: {
                        $dateFromParts: {
                            year: "$_id.year",
                            month: "$_id.month",
                            day: "$_id.day"
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$date" } },
                    totalMessages: 1,
                    suspiciousMessages: 1,
                    details: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        // Aggregate Call Log data
        const callLogData = await CallLog.aggregate([
            {
                $addFields: {
                    date: {
                        $dateFromString: { dateString: "$date" }
                    }
                }
            },
            {
                $match: {
                    date: { $gte: new Date('2024-01-01T00:00:00Z'), $lte: new Date() }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$date" },
                        month: { $month: "$date" },
                        day: { $dayOfMonth: "$date" }
                    },
                    details: { $push: { number: "$number", type: "$type", duration: "$duration" } },
                    totalCalls: { $sum: 1 },
                    incomingCalls: { $sum: { $cond: [{ $eq: ["$type", "received"] }, 1, 0] } },
                    outgoingCalls: { $sum: { $cond: [{ $eq: ["$type", "outgoing"] }, 1, 0] } },
                    missedCalls: { $sum: { $cond: [{ $eq: ["$type", "missed"] }, 1, 0] } }
                }
            },
            {
                $addFields: {
                    date: {
                        $dateFromParts: {
                            year: "$_id.year",
                            month: "$_id.month",
                            day: "$_id.day"
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$date" } },
                    totalCalls: 1,
                    incomingCalls: 1,
                    outgoingCalls: 1,
                    missedCalls: 1,
                    details: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        // Combine SMS and Call Log timeline data
        const combinedTimeline = [];

        const allDates = new Set([
            ...smsData.map(entry => entry.date),
            ...callLogData.map(entry => entry.date)
        ]);

        allDates.forEach(date => {
            const smsEntry = smsData.find(entry => entry.date === date) || {};
            const callEntry = callLogData.find(entry => entry.date === date) || {};

            combinedTimeline.push({
                date,
                totalMessages: smsEntry.totalMessages || 0,
                suspiciousMessages: smsEntry.suspiciousMessages || 0,
                smsDetails: smsEntry.details || [],
                totalCalls: callEntry.totalCalls || 0,
                incomingCalls: callEntry.incomingCalls || 0,
                outgoingCalls: callEntry.outgoingCalls || 0,
                missedCalls: callEntry.missedCalls || 0,
                callDetails: callEntry.details || []
            });
        });

        combinedTimeline.sort((a, b) => new Date(a.date) - new Date(b.date));

        // Save the combined timeline data into the database
        await TimelineAnalysis.deleteMany({}); // Optionally clear previous data
        await TimelineAnalysis.insertMany(combinedTimeline);

        // Send the results in the response
        res.json({
            message: "Timeline analysis completed successfully.",
            timeline: combinedTimeline
        });
    } catch (err) {
        console.error('Error performing timeline analysis:', err);
        res.status(500).send('Error performing timeline analysis');
    }
});



app.get('/url-analysis', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const spamPatterns = [/example-spam-domain\.com/, /another-spam-site\.net/];

        const smsWithUrls = await SMS.find({ body: /http:\/\/|https:\/\/|www\./i });

        const spamUrlData = [];
        const nonSpamUrlData = [];

        smsWithUrls.forEach(sms => {
            const urls = extractUrls(sms.body);
            console.log('Extracted URLs:', urls); // Log extracted URLs
            const containsSpam = urls.some(url => spamPatterns.some(pattern => pattern.test(url)));

            const smsData = {
                sender: sms.address,
                date: sms.date,
                body: sms.body,
                urls: urls
            };

            if (containsSpam) {
                spamUrlData.push(smsData);
            } else {
                nonSpamUrlData.push(smsData);
            }
        });

        console.log('Spam URL Data:', spamUrlData); // Log spam URL data

        await SpamURLAnalysis.deleteMany({});
        await SpamURLAnalysis.insertMany(spamUrlData);

        res.json({
            spamUrls: spamUrlData,
            nonSpamUrls: nonSpamUrlData,
        });
    } catch (err) {
        console.error('Error performing URL analysis:', err);
        res.status(500).send('Error performing URL analysis');
    }
});

// Function to extract URLs from text
const extractUrls = (text) => {
    const urlPattern = /((http|https):\/\/[^\s]+)/g;
    return text.match(urlPattern) || [];
};




app.get('/data-correlation', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        // Fetch SMS data from MongoDB
        const smsData = await SMS.aggregate([
            { $group: { _id: "$address", smsCount: { $sum: 1 }, messages: { $push: "$$ROOT" } } },
            { $sort: { smsCount: -1 } },
        ]);

        // Fetch correlated call logs for each SMS data entry
        const correlatedNumbersPromises = smsData.map(async (sms) => {
            try {
                const callLogs = await CallLog.find({ number: sms._id });
                return {
                    number: sms._id,
                    smsCount: sms.smsCount,
                    messages: sms.messages, // Include SMS details
                    callLogs,
                };
            } catch (error) {
                console.error(`Error fetching call logs for number ${sms._id}:`, error);
                return {
                    number: sms._id,
                    smsCount: sms.smsCount,
                    messages: sms.messages,
                    callLogs: [],
                };
            }
        });

        // Wait for all correlated numbers to be processed
        const results = await Promise.all(correlatedNumbersPromises);

        // Log the results to verify the data
        console.log('Results to be inserted:', results);

        // Validate results before saving
        const validResults = results.filter(result => result.number); // Filter out invalid entries

        // Save the results into the database
        await DataCorrelation.deleteMany({}); // Optionally clear previous data
        await DataCorrelation.insertMany(validResults);

        // Prepare response
        res.json(validResults);
    } catch (err) {
        console.error('Error performing data correlation:', err);
        res.status(500).send('Error performing data correlation');
    }

});



app.listen(port, async () => {
    console.log(`Server running on http://localhost:${port}`);
});
  