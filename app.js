const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: false
}));

// DB setup
const db = new sqlite3.Database(path.join(__dirname, "database.sqlite"), (err) => {
  if (err) console.error(err.message);
  else console.log("Connected to SQLite DB");
});
db.run("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
db.run("CREATE TABLE IF NOT EXISTS servers(id INTEGER PRIMARY KEY, name TEXT, owner TEXT)");

// Routes
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users(username, password) VALUES (?, ?)", [username, hashed], (err) => {
    if (err) return res.send("User already exists!");
    res.redirect("/login");
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, row) => {
    if (!row) return res.send("User not found!");
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.send("Wrong password!");
    req.session.user = row.username;
    res.redirect("/dashboard");
  });
});

app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  db.all("SELECT * FROM servers WHERE owner=?", [req.session.user], (err, servers) => {
    res.render("dashboard", { user: req.session.user, servers });
  });
});

app.post("/create-server", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  const { name } = req.body;
  db.run("INSERT INTO servers(name, owner) VALUES (?, ?)", [name, req.session.user], () => {
    res.redirect("/dashboard");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => console.log("Server running on http://localhost:" + PORT));
