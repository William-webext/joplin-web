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
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const PUBLISHED_DATA_FILE = path.join(DATA_DIR, 'published_notebooks.json');
const GROUPS_DATA_FILE = path.join(DATA_DIR, 'groups.json');

if (!fs.existsSync(PUBLISHED_DATA_FILE)) fs.writeFileSync(PUBLISHED_DATA_FILE, JSON.stringify({ folders: [], notes: [] }, null, 2));
if (!fs.existsSync(GROUPS_DATA_FILE)) fs.writeFileSync(GROUPS_DATA_FILE, JSON.stringify([], null, 2));

function getPublishedData() {
  try { return JSON.parse(fs.readFileSync(PUBLISHED_DATA_FILE, 'utf-8')); } catch (e) { return { folders: [], notes: [] }; }
}
function savePublishedData(data) { fs.writeFileSync(PUBLISHED_DATA_FILE, JSON.stringify(data, null, 2)); }

function getGroupsData() {
  try { return JSON.parse(fs.readFileSync(GROUPS_DATA_FILE, 'utf-8')); } catch (e) { return []; }
}
function saveGroupsData(groups) { fs.writeFileSync(GROUPS_DATA_FILE, JSON.stringify(groups, null, 2)); }

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

async function authenticateRequest(auth) {
  if (!auth || !auth.email || !auth.password) return false;
  try {
    const result = await pool.query('SELECT password FROM users WHERE email = $1', [auth.email]);
    if (result.rows.length === 0) return false;
    return await bcrypt.compare(auth.password, result.rows[0].password);
  } catch (e) {
    return false;
  }
}

app.get('/api/users-and-groups', async (req, res) => {
  try {
    const userRes = await pool.query('SELECT id, email, is_admin FROM users ORDER BY email ASC');
    const groups = getGroupsData();
    res.json({ users: userRes.rows, groups });
  } catch (err) {
    res.status(500).json({ error: 'Errore lettura utenti/gruppi' });
  }
});

app.post('/api/admin/groups', async (req, res) => {
  const { groups } = req.body;
  if (!Array.isArray(groups)) return res.status(400).json({ error: 'Dati non validi' });
  saveGroupsData(groups);
  res.json({ success: true });
});

app.get('/api/published-list', (req, res) => {
  const data = getPublishedData();
  const list = data.folders.map(f => ({
    id: f.id,
    parent_id: f.parent_id || '',
    title: f.title,
    visibility: f.visibility,
    allowedUsers: f.allowedUsers || [],
    allowedGroups: f.allowedGroups || [],
    notesCount: data.notes.filter(n => n.parent_id === f.id).length,
    updated_at: f.updated_at
  }));
  res.json({ folders: list });
});

app.post('/api/publish', async (req, res) => {
  const { auth, folder, folders, notes, updateOnlyVisibility } = req.body;

  const isAuthenticated = await authenticateRequest(auth);
  if (!isAuthenticated) {
    return res.status(401).json({ error: 'Authentication failed. Invalid email or password in plugin settings.' });
  }

  const targetFolders = folders || (folder ? [folder] : []);
  if (targetFolders.length === 0) return res.status(400).json({ error: 'Missing folder data' });

  const currentData = getPublishedData();
  const folderIds = targetFolders.map(f => f.id);

  if (targetFolders[0].visibility === 'remove') {
    currentData.folders = currentData.folders.filter(f => !folderIds.includes(f.id));
    currentData.notes = currentData.notes.filter(n => !folderIds.includes(n.parent_id));
  } else if (updateOnlyVisibility) {
    targetFolders.forEach(tf => {
      const target = currentData.folders.find(f => f.id === tf.id);
      if (target) {
        target.visibility = tf.visibility;
        target.allowedUsers = tf.allowedUsers || [];
        target.allowedGroups = tf.allowedGroups || [];
      }
    });
  } else {
    currentData.folders = currentData.folders.filter(f => !folderIds.includes(f.id));
    currentData.notes = currentData.notes.filter(n => !folderIds.includes(n.parent_id));

    targetFolders.forEach(tf => {
      currentData.folders.push({
        id: tf.id,
        parent_id: tf.parent_id || '',
        title: tf.title,
        visibility: tf.visibility || 'private',
        allowedUsers: tf.allowedUsers || [],
        allowedGroups: tf.allowedGroups || [],
        updated_at: Date.now()
      });
    });

    if (notes && Array.isArray(notes)) {
      notes.forEach(note => {
        currentData.notes.push({
          id: note.id,
          parent_id: note.parent_id,
          title: note.title,
          body: note.body,
          updated_time: note.user_updated_time || note.updated_time || Date.now()
        });
      });
    }
  }

  savePublishedData(currentData);
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT id, email, is_admin, password FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Email non trovata' });
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Password errata' });

    res.json({ success: true, userId: user.id, email: user.email, isAdmin: !!user.is_admin });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

app.get('/api/data', async (req, res) => {
  const userId = req.query.userId;
  const isAuth = !!userId;

  let currentUserEmail = '';
  if (isAuth) {
    try {
      const uRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
      if (uRes.rows.length > 0) currentUserEmail = uRes.rows[0].email;
    } catch (e) {}
  }

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
        WHERE (i.owner_id = $1 OR ui.user_id = $1 OR su.user_id = $1 OR i.jop_type IN (5, 6))
        AND i.jop_type IN (1, 2, 5, 6)
      `;
      const result = await pool.query(queryText, [userId]);
      let foldersRaw = [];

      result.rows.forEach(row => {
        let parsedContent = {};
        try { parsedContent = JSON.parse(row.content.toString('utf-8')); } catch (e) { return; }
        if (Number(parsedContent.deleted_time || 0) > 0 || Number(parsedContent.is_conflict || 0) > 0) return;

        const effectiveParentId = row.jop_parent_id || parsedContent.parent_id || '';
        if (row.jop_type === 2) {
          let extractedIcon = '';
          if (parsedContent.icon) {
            try { extractedIcon = JSON.parse(parsedContent.icon).emoji || ''; } catch (e) { extractedIcon = parsedContent.icon; }
          }
          foldersRaw.push({ id: row.jop_id, parent_id: effectiveParentId, icon: extractedIcon || '📁', title: parsedContent.title || 'Senza Titolo', isPublished: false });
        } else if (row.jop_type === 1) {
          allNotes.push({ id: row.jop_id, parent_id: effectiveParentId, title: parsedContent.title || 'Nuova Nota', body: parsedContent.body || '', updated_time: Number(parsedContent.user_updated_time || parsedContent.updated_time || 0) });
          noteIdsSet.add(row.jop_id);
        } else if (row.jop_type === 5) {
          tags.push({ id: row.jop_id, title: parsedContent.title || 'Tag' });
        } else if (row.jop_type === 6) {
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
        if (!isOrphan) { allFolders.push(f); folderIdsSet.add(f.id); }
      });

      allNotes.forEach(note => {
        const myTagIds = noteTags.filter(nt => nt.note_id === note.id).map(nt => nt.tag_id);
        note.tags = tags.filter(t => myTagIds.includes(t.id)).map(t => t.title);
      });

    } catch (err) { console.error("Errore DB Live:", err); }
  }

  const publishedData = getPublishedData();
  const groupsData = getGroupsData();

  const userGroupIds = groupsData.filter(g => g.members && g.members.includes(currentUserEmail)).map(g => g.id);

  const visiblePublishedFolders = publishedData.folders.filter(f => {
    if (f.visibility === 'public') return true;
    if (!isAuth) return false;
    if (f.visibility === 'private') return true;
    if (f.visibility === 'custom') {
      const allowedUsers = f.allowedUsers || [];
      const allowedGroups = f.allowedGroups || [];
      return allowedUsers.includes(currentUserEmail) || allowedGroups.some(gId => userGroupIds.includes(gId));
    }
    return false;
  });

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
        parent_id: f.parent_id || '', 
        icon: iconTag, 
        title: f.title, 
        isPublished: true 
      });
      folderIdsSet.add(f.id);
    }
  });

  const visiblePublishedFolderIds = visiblePublishedFolders.map(f => f.id);
  const visiblePublishedNotes = publishedData.notes.filter(n => visiblePublishedFolderIds.includes(n.parent_id));

  visiblePublishedNotes.forEach(n => {
    if (!noteIdsSet.has(n.id)) {
      allNotes.push({ id: n.id, parent_id: n.parent_id, title: n.title, body: n.body, updated_time: n.updated_time, tags: ['Pubblicato'] });
      noteIdsSet.add(n.id);
    }
  });

  // RECUPERO IN TEMPO REALE DA POSTGRESQL PER I TACCUINI PUBBLICATI
  if (visiblePublishedFolderIds.length > 0) {
    try {
      const dbLiveQuery = `SELECT jop_id, jop_parent_id, content FROM items WHERE jop_type = 1`;
      const dbLiveResult = await pool.query(dbLiveQuery);
      
      dbLiveResult.rows.forEach(row => {
        let parsed = {};
        try { parsed = JSON.parse(row.content.toString('utf-8')); } catch(e) { return; }
        if (Number(parsed.deleted_time || 0) > 0 || Number(parsed.is_conflict || 0) > 0) return;

        const effParent = row.jop_parent_id || parsed.parent_id || '';
        if (visiblePublishedFolderIds.includes(effParent)) {
          const freshNote = {
            id: row.jop_id,
            parent_id: effParent,
            title: parsed.title || 'Nuova Nota',
            body: parsed.body || '',
            updated_time: Number(parsed.user_updated_time || parsed.updated_time || 0),
            tags: ['Pubblicato']
          };

          const existingIndex = allNotes.findIndex(n => n.id === row.jop_id);
          if (existingIndex >= 0) {
            allNotes[existingIndex] = freshNote;
          } else {
            allNotes.push(freshNote);
            noteIdsSet.add(row.jop_id);
          }
        }
      });
    } catch (err) {
      console.error("Errore override live da DB:", err);
    }
  }

  res.json({ folders: allFolders, notes: allNotes, isAuth });
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

app.listen(port, () => console.log(`🚀 Joplin Web Viewer su http://localhost:${port}`));
