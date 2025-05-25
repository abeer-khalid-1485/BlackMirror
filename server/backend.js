
const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const port = 3000;

const clientPath = path.join(__dirname, "../client");
const assetsPath = path.join(__dirname, "../assets");

app.use(express.static(clientPath));
app.use("/assets", express.static(assetsPath));
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.sendFile(path.join(clientPath, "login.html"));
});

const reportDbPath = path.join(__dirname, "report_log.db");

function initializeDatabase() {
  const db = new sqlite3.Database(reportDbPath);
  db.run("CREATE TABLE IF NOT EXISTS phishing_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, reported_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
  db.close();
}

initializeDatabase();

// ✅ فحص باستخدام Google Safe Browsing API
app.post("/check-url", async (req, res) => {
  const url = req.body.url;
  if (!url) {
    return res.status(400).json({ error: "لم يتم توفير رابط" });
  }

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyCmN0trY5S4Yh83_NLOvM7uHbAndS2QKYM`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "blackmirror-project",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });

    const data = await response.json();

    if (data && data.matches) {
      res.json({ safe: false, info: "الرابط مشبوه حسب Google Safe Browsing" });
    } else {
      res.json({ safe: true, info: "الرابط آمن حسب Google" });
    }
  } catch (err) {
    console.error("API error:", err.message);
    res.status(500).json({ error: "فشل الاتصال بـ Google API" });
  }
});

// 📩 بلاغ
app.post("/report-url", (req, res) => {
  const reportedUrl = req.body.url;
  if (!reportedUrl) {
    return res.status(400).json({ error: "الرابط مفقود" });
  }

  const db = new sqlite3.Database(reportDbPath);
  db.run("INSERT INTO phishing_reports (url) VALUES (?)", [reportedUrl], (err) => {
    if (err) {
      console.error("DB error:", err.message);
      res.status(500).json({ error: "مشكلة في قاعدة البيانات" });
    } else {
      res.json({ success: true, message: "تم تسجيل البلاغ بنجاح" });
    }
    db.close();
  });
});

app.listen(port, () => {
  console.log(`✅ Server running with Google Safe Browsing API at http://localhost:${port}`);
});
