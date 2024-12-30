const express = require('express');
const bcrypt = require('bcrypt');
const collection = require('./config');
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Setting the view engine
app.set('view engine', 'ejs');

// Routes
app.get("/", (req, res) => {
    res.render("login");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if user exists
        const user = await collection.findOne({ username });
        if (!user) {
            return res.render("login", { error: "User does not exist" });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.render("login", { error: "Invalid password" });
        }

        // If both checks pass, redirect to success page or dashboard
        res.render("dashboard", { username: user.username });
    } catch (err) {
        console.error("Error during login:", err.message);
        res.render("login", { error: "An error occurred while logging in." });
    }
});

app.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await collection.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.render("signup", { error: "User or email already exists. Please try a different username or email." });
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Save the new user to the database
        const newUser = new collection({ username, email, password: hashedPassword });
        await newUser.save();

        res.render("login", { success: "User registered successfully! Please login." });
        console.log("User data saved successfully:", newUser);
    } catch (err) {
        console.error("Error saving user data:", err.message);
        res.render("signup", { error: "An error occurred while registering the user." });
    }
});

// Start the server
const port = 5000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
