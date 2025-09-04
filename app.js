// index.js
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { nanoid } = require("nanoid");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");

// Config
const PORT = 3000;
const JWT_SECRET = "replace_this_with_a_real_secret"; // replace in production
const DEFAULT_TTL = 60 * 60 * 24 * 7; // 7 days
const DB_FILE = "db.json";

// Load / Save simple JSON DB
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [], shorts: [] };
  return JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
}
function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
let db = loadDB();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing Authorization header" });
  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Signup
app.post("/api/auth/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (username.length < 3) return res.status(400).json({ error: "Username too short" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 chars" });

  if (db.users.find(u => u.username === username))
    return res.status(409).json({ error: "Username already taken" });

  const hash = await bcrypt.hash(password, 10);
  const user = { id: nanoid(), username, hash };
  db.users.push(user);
  saveDB(db);

  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: "Invalid username or password" });

  const ok = await bcrypt.compare(password, user.hash);
  if (!ok) return res.status(400).json({ error: "Invalid username or password" });

  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Create short link
app.post("/api/shorten", auth, (req, res) => {
  const { url, customCode, ttlSeconds } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });
  try { new URL(url); } catch { return res.status(400).json({ error: "Invalid URL" }); }

  let code = customCode || nanoid(7);
  if (db.shorts.find(s => s.code === code))
    return res.status(409).json({ error: "Code already in use" });

  const now = Date.now();
  const ttl = Number(ttlSeconds) || DEFAULT_TTL;
  const entry = {
    id: nanoid(),
    owner: req.user.id,
    url,
    code,
    createdAt: now,
    expiresAt: now + ttl * 1000,
    clicks: 0
  };
  db.shorts.push(entry);
  saveDB(db);

  res.json({ short: `http://localhost:${PORT}/${code}`, code, expiresAt: entry.expiresAt });
});

// List user's links
app.get("/api/shorts", auth, (req, res) => {
  const list = db.shorts.filter(s => s.owner === req.user.id);
  res.json({ list });
});

// Redirect
app.get("/:code", (req, res) => {
  const entry = db.shorts.find(s => s.code === req.params.code);
  if (!entry) return res.status(404).send("<h1>Not found</h1>");
  if (Date.now() > entry.expiresAt) return res.status(410).send("<h1>Link expired</h1>");
  entry.clicks++;
  saveDB(db);
  res.redirect(entry.url);
});

// Serve minimal frontend (same as before)
app.get("/", (req, res) => {
  res.send(`<!doctype html>
<html>
<head>
  <title>URL Shortener</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
  <div id="root"></div>
  <script crossorigin src="https://unpkg.com/react@18/umd/react.development.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
  <script>
  const e = React.createElement;
  function App(){
    const [token, setToken] = React.useState(localStorage.getItem("token") || "");
    const [username, setU] = React.useState("");
    const [password, setP] = React.useState("");
    const [url, setUrl] = React.useState("");
    const [shorts, setShorts] = React.useState([]);
    const [loading, setLoading] = React.useState(false);

    async function api(path, method="GET", body){
      const res = await fetch(path, {
        method,
        headers: {
          "Content-Type":"application/json",
          ...(token? {Authorization: "Bearer "+token}: {})
        },
        body: body? JSON.stringify(body): undefined
      });
      const json = await res.json().catch(()=>null);
      if(!res.ok){
        // auto logout if token expired
        if(res.status === 401){ logout(); }
        throw json;
      }
      return json;
    }

    async function login(signup){
      try{
        setLoading(true);
        const data = await api("/api/auth/"+(signup?"signup":"login"),"POST",{username,password});
        setToken(data.token);
        localStorage.setItem("token",data.token);
        setU(""); setP("");
        load();
      }catch(err){ alert(err.error || "Error"); }
      finally{ setLoading(false); }
    }

    async function create(){
      try{ await api("/api/shorten","POST",{url}); setUrl(""); load(); }
      catch(err){ alert(err.error || "Error"); }
    }

    async function load(){
      if(!token) return;
      try{
        const data = await api("/api/shorts");
        setShorts(data.list);
      }catch(err){ alert(err.error || "Error"); }
    }

    function logout(){
      setToken(""); localStorage.removeItem("token"); setShorts([]);
    }

    React.useEffect(()=>{ if(token) load(); },[token]);

    if(!token){
      return e("div",{className:"card p-3"},
        e("h4",{className:"mb-3"},"Login / Signup"),
        e("input",{className:"form-control mb-2",placeholder:"username",value:username,onChange:e=>setU(e.target.value)}),
        e("input",{type:"password",className:"form-control mb-2",placeholder:"password",value:password,onChange:e=>setP(e.target.value)}),
        e("button",{disabled:loading,className:"btn btn-primary me-2",onClick:()=>login(false)},"Login"),
        e("button",{disabled:loading,className:"btn btn-secondary",onClick:()=>login(true)},"Signup")
      );
    }

    return e("div",null,
      e("div",{className:"mb-3"},
        e("h4",{className:"mb-3"},"URL Shortener"),
        e("input",{className:"form-control mb-2",placeholder:"https://example.com",value:url,onChange:e=>setUrl(e.target.value)}),
        e("button",{className:"btn btn-success",onClick:create},"Shorten"),
        e("button",{className:"btn btn-link ms-2",onClick:logout},"Logout")
      ),
      e("ul",{className:"list-group"},
        shorts.map(s => e("li",{key:s.id,className:"list-group-item"},
          e("a",{href:"/"+s.code,target:"_blank"},location.origin+"/"+s.code),
          " → "+s.url,
          " (Clicks: "+s.clicks+")"
        ))
      )
    );
  }
  ReactDOM.createRoot(document.getElementById("root")).render(e(App));
</script>

</body>
</html>`);
});

app.listen(PORT, () => console.log("\`App running on http://localhost:\${PORT}\`"));
