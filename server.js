const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.static('public'));
app.use(express.json({ limit: '50mb' })); 
const port = 3000;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const PUBLISHED_DATA_FILE = path.join(DATA_DIR, 'published_notebooks.json');

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

// LISTA DEI TACCUINI PUBBLICATI PER IL PANNELLO DEL PLUGIN
app.get('/api/published-list', (req, res) => {
  const data = getPublishedData();
  const list = data.folders.map(f => ({
    id: f.id,
    title: f.title,
    visibility: f.visibility,
    notesCount: data.notes.filter(n => n.parent_id === f.id).length,
    updated_at: f.updated_at
  }));
  res.json({ folders: list });
});

// RECEIVE PUBLISH, UPDATE VISIBILITY OR REMOVE FROM PLUGIN
app.post('/api/publish', (req, res) => {
  const { folder, notes, updateOnlyVisibility } = req.body;

  if (!folder || !folder.id) {
    return res.status(400).json({ error: 'Dati incompleti' });
  }

  const currentData = getPublishedData();

  if (folder.visibility === 'remove') {
    currentData.folders = currentData.folders.filter(f => f.id !== folder.id);
    currentData.notes = currentData.notes.filter(n => n.parent_id !== folder.id);
  } else if (updateOnlyVisibility) {
    const target = currentData.folders.find(f => f.id === folder.id);
    if (target) target.visibility = folder.visibility;
  } else {
    currentData.folders = currentData.folders.filter(f => f.id !== folder.id);
    currentData.notes = currentData.notes.filter(n => n.parent_id !== folder.id);

    currentData.folders.push({
      id: folder.id,
      title: folder.title,
      visibility: folder.visibility || 'private',
      updated_at: Date.now()
    });

    if (notes && Array.isArray(notes)) {
      notes.forEach(note => {
        currentData.notes.push({
          id: note.id,
          parent_id: folder.id,
          title: note.title,
          body: note.body,
          updated_time: note.user_updated_time || note.updated_time || Date.now()
        });
      });
    }
  }

  savePublishedData(currentData);
  res.json({ success: true, message: 'Operazione completata' });
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

// UNIFIED DATA FETCHING
app.get('/api/data', async (req, res) => {
  const userId = req.query.userId;
  const isAuth = !!userId;

  let allFolders = [];
  let allNotes = [];
  let tags = [];
  let noteTags = [];

  const folderIdsSet = new Set();
  const noteIdsSet = new Set();

  if (isAuth) {
    try {
      const queryText = `
        SELECT DISTINCT i.jop_id, i.jop_parent_id, i.jop_type, i.content 
        FROM items i
        LEFT JOIN user_items ui ON (ui.item_id = i.id OR ui.item_id = i.jop_id)
        LEFT JOIN shares s ON (s.item_id = i.id OR s.item_id = i.jop_id OR s.folder_id = i.jop_id)
        LEFT JOIN share_users su ON su.share_id = s.id
        WHERE (
          i.owner_id = $1 
          OR ui.user_id = $1 
          OR su.user_id = $1
          OR i.jop_type IN (5, 6)
        )
        AND i.jop_type IN (1, 2, 5, 6)
      `;

      const result = await pool.query(queryText, [userId]);
      let foldersRaw = [];

      result.rows.forEach(row => {
        let parsedContent = {};
        try { parsedContent = JSON.parse(row.content.toString('utf-8')); } catch (e) { return; }

        if (Number(parsedContent.deleted_time || 0) > 0 || 
            Number(parsedContent.user_deleted_time || 0) > 0 || 
            Number(parsedContent.is_conflict || 0) > 0 || 
            parsedContent.in_trash || parsedContent.is_trash) return;

        const effectiveParentId = row.jop_parent_id || parsedContent.parent_id || '';

        if (row.jop_type === 2) {
          let extractedIcon = '';
          if (parsedContent.icon) {
              try { extractedIcon = JSON.parse(parsedContent.icon).emoji || ''; } catch (e) { extractedIcon = parsedContent.icon; }
          }
          foldersRaw.push({ 
            id: row.jop_id, 
            parent_id: effectiveParentId, 
            icon: extractedIcon || '📁', 
            title: parsedContent.title || 'Senza Titolo',
            isPublished: false
          });
        } 
        else if (row.jop_type === 1) {
          allNotes.push({ 
            id: row.jop_id, 
            parent_id: effectiveParentId, 
            title: parsedContent.title || 'Nuova Nota', 
            body: parsedContent.body || '', 
            updated_time: Number(parsedContent.user_updated_time || parsedContent.updated_time || 0) 
          });
          noteIdsSet.add(row.jop_id);
        }
        else if (row.jop_type === 5) {
          tags.push({ id: row.jop_id, title: parsedContent.title || 'Tag' });
        }
        else if (row.jop_type === 6) {
          noteTags.push({ note_id: parsedContent.note_id, tag_id: parsedContent.tag_id });
        }
      });

      const folderMap = new Map(foldersRaw.map(f => [f.id, f]));
      foldersRaw.forEach(f => {
        let current = f;
        let isOrphan = false;
        while (current.parent_id) {
          if (!folderMap.has(current.parent_id)) { isOrphan = true; break; }
          current = folderMap.get(current.parent_id);
        }
        if (!isOrphan) {
          allFolders.push(f);
          folderIdsSet.add(f.id);
        }
      });

      allNotes.forEach(note => {
        const myTagIds = noteTags.filter(nt => nt.note_id === note.id).map(nt => nt.tag_id);
        note.tags = tags.filter(t => myTagIds.includes(t.id)).map(t => t.title);
      });

    } catch (err) {
      console.error("Errore lettura DB Live:", err);
    }
  }

  const publishedData = getPublishedData();
  const visiblePublishedFolders = publishedData.folders.filter(f => isAuth || f.visibility === 'public');

  visiblePublishedFolders.forEach(f => {
    if (folderIdsSet.has(f.id)) {
      const existingFolder = allFolders.find(folder => folder.id === f.id);
      if (existingFolder) {
        existingFolder.isPublished = true;
        existingFolder.icon = f.visibility === 'public' ? '🌍' : '🔒';
      }
    } else {
      const iconTag = f.visibility === 'public' ? '🌍' : '🔒';
      allFolders.push({
        id: f.id,
        parent_id: '',
        icon: iconTag,
        title: `${f.title} (Pubblicato)`,
        isPublished: true
      });
      folderIdsSet.add(f.id);
    }
  });

  const visiblePublishedFolderIds = visiblePublishedFolders.map(f => f.id);
  const visiblePublishedNotes = publishedData.notes.filter(n => visiblePublishedFolderIds.includes(n.parent_id));

  visiblePublishedNotes.forEach(n => {
    if (!noteIdsSet.has(n.id)) {
      allNotes.push({
        id: n.id,
        parent_id: n.parent_id,
        title: n.title,
        body: n.body,
        updated_time: n.updated_time,
        tags: ['Pubblicato']
      });
      noteIdsSet.add(n.id);
    }
  });

  res.json({ folders: allFolders, notes: allNotes, isAuth });
});

app.get('/api/debug', (req, res) => {
  const data = getPublishedData();
  res.json({
    dataDir: DATA_DIR,
    filePath: PUBLISHED_DATA_FILE,
    fileExists: fs.existsSync(PUBLISHED_DATA_FILE),
    foldersCount: data.folders ? data.folders.length : 0,
    notesCount: data.notes ? data.notes.length : 0
  });
});

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
