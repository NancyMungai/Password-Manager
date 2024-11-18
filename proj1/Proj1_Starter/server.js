const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = 3000;

const db = new Database(path.join(__dirname, 'data', 'passwords.db'));

// Create a table for storing passwords
db.exec(`
    CREATE TABLE IF NOT EXISTS passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL,
      password TEXT NOT NULL
    )
  `);

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'frontend')));

// Middleware for parsing JSON requests
app.use(express.json());

// API routes to interact with Keychain
const { Keychain } = require('./password-manager');
let keychain;

app.post('/init', async (req, res) => {
    try {
        const { password } = req.body;
        keychain = await Keychain.init(password);
        res.json({ message: 'Keychain initialized!' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add a new password
app.post('/set', async(req, res) => {
    const { domain, password } = req.body;
  
//     try {
//       const stmt = db.prepare('INSERT INTO passwords (domain, password) VALUES (?, ?)');
//       stmt.run(domain, password);
//       res.json({ message: 'Password saved!' });
//     } catch (error) {
//       console.error(`Error saving password: ${error.message}`);
//       res.status(500).json({ error: 'Failed to save password' });
//     }
//   });
try {
    await keychain.set(domain, password);
    res.json({ message: 'Password encrypted and saved!' });
} catch (error) {
    console.error(`Error saving password: ${error.message}`);
    res.status(500).json({ error: 'Failed to save password' });
}
});


// Get all saved passwords
app.post('/get', async (req, res) => {
    const { domain } = req.body;
    try {
        const decryptedPassword = await keychain.get(domain);
        if (!decryptedPassword) {
            return res.status(404).json({ error: 'Password not found' });
        }
        res.json({ domain, password: decryptedPassword });
    } catch (error) {
        console.error(`Error retrieving password: ${error.message}`);
        res.status(500).json({ error: 'Failed to retrieve password' });
    }
});
//     try {
//       const stmt = db.prepare('SELECT * FROM passwords');
//       const passwords = stmt.all();
//       res.json(passwords);
//     } catch (error) {
//       console.error(`Error retrieving passwords: ${error.message}`);
//       res.status(500).json({ error: 'Failed to retrieve passwords' });
//     }
//   });

app.get('/getAll', async (req, res) => {
    try {
        const allPasswords = await keychain.getAll();
        console.log('Returning all passwords:', allPasswords);
        res.json(allPasswords);
    } catch (error) {
        console.error('Error in /getAll:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Delete a password by ID
app.post('/delete', (req, res) => {
    const { id } = req.body;
  
    try {
      const stmt = db.prepare('DELETE FROM passwords WHERE id = ?');
      stmt.run(id);
      res.json({ message: 'Password deleted!' });
    } catch (error) {
      console.error(`Error deleting password: ${error.message}`);
      res.status(500).json({ error: 'Failed to delete password' });
    }
  });

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
