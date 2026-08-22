const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.static('public'));
app.use(express.json({ limit: '50mb' })); 
const port = 3000;

const PUBLISHED_DATA_FILE = path.join(__dirname, 'published_notebooks.json');

if (!fs.existsSync(PUBLISHED_DATA_FILE)) {
  fs.writeFileSync(PUBLISHED_DATA_FILE, JSON.stringify({ folders: [], notes: [] }, null, 2));
}

function getPublishedData() {
  try {
    return JSON.parse(fs.readFileSync(PUBLISHED_DATA_FILE, 'utf-8'));
  } catch (e) {
    return { folders: [], notes: [] };
  }
}

function savePublishedData(data) {
  fs.writeFileSync(PUBLISHED_DATA_FILE, JSON.stringify(data, null, 2));
}

const pool = new Pool({
  user: process.env.DB_USER || 'joplinuser',
  host: process.env.DB_HOST || 'db',
  database: process.env.DB_NAME || 'joplin',
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT || '5432', 10),
});

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});

// ENDPOINT DI DEBUG (Mostra lo stato del file dei dati direttamente nel browser)
app.get('/api/debug', (req, res) => {
  const data = getPublishedData();
  res.json({
    filePath: PUBLISHED_DATA_FILE,
    fileExists: fs.existsSync(PUBLISHED_DATA_FILE),
    foldersCount: data.folders ? data.folders.length : 0,
    notesCount: data.notes ? data.notes.length : 0,
    rawContent: data
  });
});

// RECEIVE PUBLISH FROM PLUGIN
app.post('/api/publish', (req, res) => {
  const { folder, notes } = req.body;

  console.log("📥 Ricevuta richiesta di pubblicazione:", folder);

  if (!folder || !folder.id || !notes) {
    return res.status(400).json({ error: 'Dati incompleti' });
  }

  const currentData = getPublishedData();

  // Rimuove vecchie versioni del taccuino
  currentData.folders = currentData.folders.filter(f => f.id !== folder.id);
  currentData.notes = currentData.notes.filter(n => n.parent_id !== folder.id);

  currentData.folders.push({
    id: folder.id,
    title: folder.title,
    visibility: folder.visibility || 'private',
    updated_at: Date.now()
  });

  notes.forEach(note => {
    currentData.notes.push({
      id: note.id,
      parent_id: folder.id,
      title: note.title,
      body: note.body,
      updated_time: note.user_updated_time || note.updated_time || Date.now()
    });
  });

  savePublishedData(currentData);
  console.log("💾 Dati salvati con successo. Taccuini totali:", currentData.folders.length);
  res.json({ success: true, message: 'Taccuino pubblicato correttamente' });
});

// LOGIN API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT id, password FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Email non trovata' });
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Password errata' });

    res.json({ success: true, userId: user.id });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// API PUBLISHED DATA
app.get('/api/published-data', (req, res) => {
  const userId = req.query.userId;
  const isAuth = !!userId;
  const data = getPublishedData();

  const visibleFolders = data.folders.filter(f => isAuth || f.visibility === 'public');
  const visibleFolderIds = visibleFolders.map(f => f.id);
  const visibleNotes = data.notes.filter(n => visibleFolderIds.includes(n.parent_id));

  res.json({ folders: visibleFolders, notes: visibleNotes, isAuth });
});

// RESOURCE DOWNLOAD API
app.get('/api/resource/:id', async (req, res) => {
  const resourceId = req.params.id;
  try {
    const result = await pool.query("SELECT name, content FROM items WHERE jop_id = $1 OR name LIKE $2", [resourceId, '%' + resourceId + '%']);
    let mimeType = 'application/octet-stream';
    let fileName = resourceId;
    let binaryContent = null;

    for (let row of result.rows) {
        if (!row.content) continue;
        const contentString = row.content.toString('utf-8');
        if (contentString.trim().startsWith('{')) {
            try {
                const meta = JSON.parse(contentString);
                if (meta.mime) mimeType = meta.mime;
                if (meta.title) fileName = meta.title;
            } catch(e) {}
        } else { binaryContent = row.content; }
    }

    if (binaryContent) {
      res.setHeader('Content-Type', mimeType);
      if (!mimeType.startsWith('image/')) res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
      res.send(binaryContent);
    } else { res.status(404).send('Risorsa non trovata'); }
  } catch (err) { res.status(500).send('Errore server'); }
});

app.listen(port, () => {
  console.log(`🚀 Joplin Web Viewer su http://localhost:${port}`);
});
