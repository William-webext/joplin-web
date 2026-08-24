const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
// Dietro un reverse proxy/tunnel (es. Cloudflare Tunnel), senza questo Express vede sempre
// l'IP del proxy invece di quello del client reale, e il rate limit sul login finirebbe
// per contare tutti gli utenti come se fossero uno solo. TRUST_PROXY=1 attiva la lettura
// di X-Forwarded-For; lascialo disattivato solo se esponi il container direttamente senza proxy.
if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}
app.use(express.static('public'));
app.use(express.json({ limit: '15mb' })); // corpo accettato prima di qualsiasi auth check: tenerlo basso limita il rischio DoS da payload enormi
const port = 3000;

// 1. INIZIALIZZAZIONE STORAGE E DATABASE SQLITE
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const sqliteDb = new Database(path.join(DATA_DIR, 'database.sqlite'));
sqliteDb.pragma('journal_mode = WAL'); // Attiva modalità WAL per elevate prestazioni in lettura

// Creazione automatica tabelle se non esistono
sqliteDb.exec(`
  CREATE TABLE IF NOT EXISTS preferences (
    user_id TEXT PRIMARY KEY,
    pinned_folders TEXT,
    highlighted_notes TEXT
  );

  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT,
    members TEXT
  );

  CREATE TABLE IF NOT EXISTS published_folders (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    title TEXT,
    visibility TEXT,
    allowed_users TEXT,
    allowed_groups TEXT,
    updated_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS published_notes (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    title TEXT,
    body TEXT,
    updated_time INTEGER
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`);

// ==========================================
// GESTIONE SESSIONI (sostituisce l'uso di userId nudo come credenziale)
// ==========================================
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 ore

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Un token opaco random (mai l'id utente) viene dato al client dopo login riuscito.
// Solo l'hash del token finisce nel DB: un dump del DB non permette di riusare le sessioni attive.
function createSession(userId, email, isAdmin) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;

  sqliteDb.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now); // pulizia lazy delle sessioni scadute
  sqliteDb.prepare(`
    INSERT INTO sessions (token_hash, user_id, email, is_admin, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(hashToken(token), userId, email, isAdmin ? 1 : 0, now, expiresAt);

  return { token, expiresAt };
}

function getSession(token) {
  if (!token) return null;
  const row = sqliteDb.prepare('SELECT user_id, email, is_admin, expires_at FROM sessions WHERE token_hash = ?').get(hashToken(token));
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    sqliteDb.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
    return null;
  }
  return { userId: row.user_id, email: row.email, isAdmin: !!row.is_admin };
}

function extractToken(req) {
  const header = req.headers['authorization'] || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

// Route protette: richiede una sessione valida, la espone come req.auth
function requireAuth(req, res, next) {
  const session = getSession(extractToken(req));
  if (!session) return res.status(401).json({ error: 'Sessione non valida o scaduta. Effettua di nuovo il login.' });
  req.auth = session;
  next();
}

// Route pubbliche che però cambiano comportamento se l'utente è autenticato (es. /api/data)
function optionalAuth(req, res, next) {
  req.auth = getSession(extractToken(req));
  next();
}

function requireAdmin(req, res, next) {
  if (!req.auth || !req.auth.isAdmin) return res.status(403).json({ error: 'Permessi amministratore richiesti.' });
  next();
}

// 2. FUNZIONALITÀ DI HELPER SQLITE (Sostituiscono i vecchi file JSON)
function getPublishedData() {
  try {
    const foldersRows = sqliteDb.prepare('SELECT id, parent_id, title, visibility, allowed_users, allowed_groups, updated_at FROM published_folders').all();
    const notesRows = sqliteDb.prepare('SELECT id, parent_id, title, body, updated_time FROM published_notes').all();

    const folders = foldersRows.map(f => ({
      id: f.id,
      parent_id: f.parent_id || '',
      title: f.title || '',
      visibility: f.visibility || 'private',
      allowedUsers: JSON.parse(f.allowed_users || '[]'),
      allowedGroups: JSON.parse(f.allowed_groups || '[]'),
      updated_at: Number(f.updated_at || Date.now())
    }));

    const notes = notesRows.map(n => ({
      id: n.id,
      parent_id: n.parent_id || '',
      title: n.title || '',
      body: n.body || '',
      updated_time: Number(n.updated_time || Date.now())
    }));

    return { folders, notes };
  } catch (e) {
    // Prima l'errore spariva nel nulla: se il DB avesse un problema (file corrotto, schema
    // disallineato dopo una migrazione a mano, ecc.) l'app tornava silenziosamente una lista
    // vuota, indistinguibile da "non c'è niente di pubblicato" — impossibile da diagnosticare.
    console.error('getPublishedData: errore nella lettura da SQLite:', e.message);
    return { folders: [], notes: [] };
  }
}

function savePublishedData(data) {
  const deleteFolders = sqliteDb.prepare('DELETE FROM published_folders');
  const insertFolder = sqliteDb.prepare(`
    INSERT INTO published_folders (id, parent_id, title, visibility, allowed_users, allowed_groups, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const deleteNotes = sqliteDb.prepare('DELETE FROM published_notes');
  const insertNote = sqliteDb.prepare(`
    INSERT INTO published_notes (id, parent_id, title, body, updated_time)
    VALUES (?, ?, ?, ?, ?)
  `);

  const transaction = sqliteDb.transaction((pubData) => {
    deleteFolders.run();
    if (Array.isArray(pubData.folders)) {
      for (const f of pubData.folders) {
        insertFolder.run(
          f.id,
          f.parent_id || '',
          f.title || '',
          f.visibility || 'private',
          JSON.stringify(f.allowedUsers || []),
          JSON.stringify(f.allowedGroups || []),
          Number(f.updated_at || Date.now())
        );
      }
    }

    deleteNotes.run();
    if (Array.isArray(pubData.notes)) {
      for (const n of pubData.notes) {
        insertNote.run(
          n.id,
          n.parent_id || '',
          n.title || '',
          n.body || '',
          Number(n.updated_time || Date.now())
        );
      }
    }
  });

  transaction(data);
}

function getGroupsData() {
  try {
    const rows = sqliteDb.prepare('SELECT id, name, members FROM groups').all();
    return rows.map(r => ({
      id: r.id,
      name: r.name || '',
      members: JSON.parse(r.members || '[]')
    }));
  } catch (e) {
    console.error('getGroupsData: errore nella lettura da SQLite:', e.message);
    return [];
  }
}

function saveGroupsData(groups) {
  const deleteStmt = sqliteDb.prepare('DELETE FROM groups');
  const insertStmt = sqliteDb.prepare('INSERT INTO groups (id, name, members) VALUES (?, ?, ?)');

  const transaction = sqliteDb.transaction((groupList) => {
    deleteStmt.run();
    for (const g of groupList) {
      insertStmt.run(
        g.id || '',
        g.name || '',
        JSON.stringify(g.members || [])
      );
    }
  });

  transaction(groups || []);
}

// 3. CONNESSIONE POSTGRESQL (JOPLIN CORE)
const pool = new Pool({
  user: process.env.DB_USER || 'joplinuser',
  host: process.env.DB_HOST || 'db',
  database: process.env.DB_NAME || 'joplin',
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT || '5432', 10),
});

// node-postgres emette "error" sui client idle del pool quando la connessione al DB si interrompe
// (riavvio del container Postgres, blip di rete sul tunnel, ecc.). Senza un listener qui, Node
// tratta l'evento come eccezione non gestita e termina l'intero processo — non solo la richiesta
// in corso. Con questo listener, l'errore viene loggato e il pool prova a riconnettersi da solo
// alla richiesta successiva, com'è normale comportamento di pg.
pool.on('error', (err) => {
  console.error('Errore imprevisto sul pool Postgres (connessione idle):', err.message);
});

// Con l'auth ora a token in Authorization header (non più cookie), il wildcard "*" non permette
// più a siti terzi di leggere risposte autenticate della vittima (il token non è accessibile
// cross-origin). Resta comunque buona norma restringere l'origine invece di lasciarla aperta a tutti:
// impostare ALLOWED_ORIGIN nell'ambiente (es. https://webnote.beerfactory.pt) per attivarlo.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || null;
if (!ALLOWED_ORIGIN) {
  console.warn('⚠️  ALLOWED_ORIGIN non impostata: CORS resta aperto a "*". Imposta ALLOWED_ORIGIN nel compose per restringerlo.');
}

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN || "*");
  res.header("Vary", "Origin");
  next();
});

// Limita i tentativi di login per IP: max 10 tentativi ogni 15 minuti.
// In-memory, va bene per un'app self-hosted a singolo processo (non serve Redis per questo volume).
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginAttempts = new Map(); // ip -> { count, resetAt }

function loginRateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = loginAttempts.get(ip);

  if (!entry || entry.resetAt < now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return next();
  }

  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
    res.setHeader('Retry-After', String(retryAfterSec));
    return res.status(429).json({ error: 'Troppi tentativi di login. Riprova più tardi.' });
  }

  entry.count += 1;
  next();
}

// Pulizia periodica delle voci scadute, per non far crescere la Map all'infinito su un processo long-running
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (entry.resetAt < now) loginAttempts.delete(ip);
  }
}, LOGIN_WINDOW_MS).unref();

// Unica fonte di verità per "email+password sono validi": prima questa stessa query e lo stesso
// bcrypt.compare erano scritti separatamente sia qui sia dentro /api/login — due copie della
// stessa logica di sicurezza da mantenere allineate è un rischio inutile (basta dimenticare di
// aggiornarne una sola in futuro per introdurre un'incoerenza).
async function findAuthenticatedUser(email, password) {
  if (!email || !password) return null;
  try {
    const result = await pool.query('SELECT id, email, is_admin, password FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return null;
    const match = await bcrypt.compare(password, result.rows[0].password);
    if (!match) return null;
    return { id: result.rows[0].id, email: result.rows[0].email, isAdmin: !!result.rows[0].is_admin };
  } catch (e) {
    return null;
  }
}

async function authenticateRequest(auth) {
  if (!auth) return false;
  return !!(await findAuthenticatedUser(auth.email, auth.password));
}

// 4. API PREFERENZE UI (SQLITE)
app.get('/api/preferences', requireAuth, (req, res) => {
  // Prima si fidava di ?userId=<qualsiasi id>: chiunque conoscesse l'id di un altro utente
  // poteva leggere le sue preferenze senza autenticarsi. Ora l'utente viene sempre dalla sessione.
  const userId = req.auth.userId;

  try { 
    const stmt = sqliteDb.prepare('SELECT pinned_folders, highlighted_notes FROM preferences WHERE user_id = ?');
    const row = stmt.get(userId);
    
    if (row) {
      res.json({
        pinnedFolders: JSON.parse(row.pinned_folders || '[]'),
        highlightedNotes: JSON.parse(row.highlighted_notes || '{}')
      });
    } else {
      res.json({ pinnedFolders: [], highlightedNotes: {} });
    }
  } catch(e) { 
    res.json({ pinnedFolders: [], highlightedNotes: {} }); 
  }
});

app.post('/api/preferences', requireAuth, (req, res) => {
  const { pinnedFolders, highlightedNotes } = req.body;
  const userId = req.auth.userId; // non più preso dal body: impediva di scrivere le preferenze di un altro utente

  try {
    const stmt = sqliteDb.prepare(`
      INSERT INTO preferences (user_id, pinned_folders, highlighted_notes)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        pinned_folders = excluded.pinned_folders,
        highlighted_notes = excluded.highlighted_notes
    `);
    
    stmt.run(
      userId,
      JSON.stringify(pinnedFolders || []),
      JSON.stringify(highlightedNotes || {})
    );
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: 'Errore salvataggio preferenze' }); 
  }
});

app.get('/api/users-and-groups', requireAuth, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT id, email, is_admin FROM users ORDER BY email ASC');
    res.json({ users: userRes.rows, groups: getGroupsData() });
  } catch (err) { res.status(500).json({ error: 'Errore lettura utenti/gruppi' }); }
});

app.post('/api/admin/groups', requireAuth, requireAdmin, async (req, res) => {
  if (!Array.isArray(req.body.groups)) return res.status(400).json({ error: 'Dati non validi' });
  saveGroupsData(req.body.groups);
  res.json({ success: true });
});

app.get('/api/published-list', requireAuth, (req, res) => {
  const data = getPublishedData();
  const list = data.folders.map(f => ({
    id: f.id, parent_id: f.parent_id || '', title: f.title, visibility: f.visibility,
    allowedUsers: f.allowedUsers || [], allowedGroups: f.allowedGroups || [],
    notesCount: data.notes.filter(n => n.parent_id === f.id).length, updated_at: f.updated_at
  }));
  res.json({ folders: list });
});

app.post('/api/publish', loginRateLimit, async (req, res) => {
  const { auth, folder, folders, notes, updateOnlyVisibility } = req.body;
  if (!(await authenticateRequest(auth))) return res.status(401).json({ error: 'Authentication failed.' });
  const targetFolders = folders || (folder ? [folder] : []);
  if (targetFolders.length === 0) return res.status(400).json({ error: 'Missing data' });

  const currentData = getPublishedData();
  const folderIds = targetFolders.map(f => f.id);

  if (targetFolders[0].visibility === 'remove') {
    currentData.folders = currentData.folders.filter(f => !folderIds.includes(f.id));
    currentData.notes = currentData.notes.filter(n => !folderIds.includes(n.parent_id));
  } else if (updateOnlyVisibility) {
    targetFolders.forEach(tf => {
      const target = currentData.folders.find(f => f.id === tf.id);
      if (target) { target.visibility = tf.visibility; target.allowedUsers = tf.allowedUsers || []; target.allowedGroups = tf.allowedGroups || []; }
    });
  } else {
    currentData.folders = currentData.folders.filter(f => !folderIds.includes(f.id));
    currentData.notes = currentData.notes.filter(n => !folderIds.includes(n.parent_id));
    targetFolders.forEach(tf => currentData.folders.push({ id: tf.id, parent_id: tf.parent_id || '', title: tf.title, visibility: tf.visibility || 'private', allowedUsers: tf.allowedUsers || [], allowedGroups: tf.allowedGroups || [], updated_at: Date.now() }));
    if (Array.isArray(notes)) notes.forEach(n => currentData.notes.push({ id: n.id, parent_id: n.parent_id, title: n.title, body: n.body, updated_time: n.user_updated_time || n.updated_time || Date.now() }));
  }
  savePublishedData(currentData);
  res.json({ success: true });
});

app.post('/api/login', loginRateLimit, async (req, res) => {
  try {
    const user = await findAuthenticatedUser(req.body.email, req.body.password);
    // Stesso messaggio generico per email inesistente e password errata: evita di rivelare quali email sono registrate (user enumeration)
    if (!user) return res.status(401).json({ error: 'Credenziali non valide' });

    const { token, expiresAt } = createSession(user.id, user.email, user.isAdmin);
    res.json({
      success: true,
      token,
      expiresAt,
      userId: user.id,
      email: user.email,
      isAdmin: user.isAdmin
    });
  } catch (err) { res.status(500).json({ error: 'Errore interno' }); }
});

app.post('/api/logout', requireAuth, (req, res) => {
  sqliteDb.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(extractToken(req)));
  res.json({ success: true });
});

app.get('/api/data', optionalAuth, async (req, res) => {
  // Prima: isAuth = !!req.query.userId, quindi chiunque poteva impersonare qualsiasi utente
  // passando il suo id nella query string, senza aver mai fatto login. Ora isAuth dipende
  // esclusivamente da una sessione verificata lato server.
  const isAuth = !!req.auth;
  const userId = isAuth ? req.auth.userId : null;
  const currentUserEmail = isAuth ? req.auth.email : '';

  let allFolders = [], allNotes = [], tags = [], noteTags = [];
  const folderIdsSet = new Set(), noteIdsSet = new Set();

  if (isAuth) {
    try {
      const queryText = `SELECT DISTINCT i.jop_id, i.jop_parent_id, i.jop_type, i.content FROM items i LEFT JOIN user_items ui ON (ui.item_id = i.id OR ui.item_id = i.jop_id) LEFT JOIN shares s ON (s.item_id = i.id OR s.item_id = i.jop_id OR s.folder_id = i.jop_id) LEFT JOIN share_users su ON su.share_id = s.id WHERE (i.owner_id = $1 OR ui.user_id = $1 OR su.user_id = $1 OR i.jop_type IN (5, 6)) AND i.jop_type IN (1, 2, 5, 6)`;
      const result = await pool.query(queryText, [userId]);
      let foldersRaw = [];

      result.rows.forEach(row => {
        let parsedContent = {};
        try { parsedContent = JSON.parse(row.content.toString('utf-8')); } catch (e) { return; }
        if (Number(parsedContent.deleted_time || 0) > 0 || Number(parsedContent.is_conflict || 0) > 0) return;

        const effectiveParentId = row.jop_parent_id || parsedContent.parent_id || '';
        if (row.jop_type === 2) {
          let extractedIcon = '';
          if (parsedContent.icon) { try { extractedIcon = JSON.parse(parsedContent.icon).emoji || ''; } catch (e) { extractedIcon = parsedContent.icon; } }
          foldersRaw.push({ id: row.jop_id, parent_id: effectiveParentId, icon: extractedIcon || '📁', title: parsedContent.title || 'Senza Titolo', isPublished: false });
        } else if (row.jop_type === 1) {
          allNotes.push({ id: row.jop_id, parent_id: effectiveParentId, title: parsedContent.title || 'Nuova Nota', body: parsedContent.body || '', updated_time: Number(parsedContent.user_updated_time || parsedContent.updated_time || 0) });
          noteIdsSet.add(row.jop_id);
        } else if (row.jop_type === 5) { tags.push({ id: row.jop_id, title: parsedContent.title || 'Tag' });
        } else if (row.jop_type === 6) { noteTags.push({ note_id: parsedContent.note_id, tag_id: parsedContent.tag_id }); }
      });

      const folderMap = new Map(foldersRaw.map(f => [f.id, f]));
      foldersRaw.forEach(f => {
        let current = f, isOrphan = false;
        const visited = new Set(); // senza questo, un parent_id ciclico causa un loop infinito e blocca il processo
        while (current.parent_id) {
          if (visited.has(current.id)) { isOrphan = true; break; }
          visited.add(current.id);
          if (!folderMap.has(current.parent_id)) { isOrphan = true; break; }
          current = folderMap.get(current.parent_id);
        }
        if (!isOrphan) { allFolders.push(f); folderIdsSet.add(f.id); }
      });

      allNotes.forEach(note => {
        const myTagIds = noteTags.filter(nt => nt.note_id === note.id).map(nt => nt.tag_id);
        note.tags = tags.filter(t => myTagIds.includes(t.id)).map(t => t.title);
      });
    } catch (err) {
      console.error('/api/data (contenuti privati utente): errore nella query a Postgres:', err.message);
    }
  }

  const publishedData = getPublishedData();
  const groupsData = getGroupsData();
  const userGroupIds = groupsData.filter(g => g.members && g.members.includes(currentUserEmail)).map(g => g.id);

  // Serve a distinguere, più sotto, le note che l'utente possiede davvero (già in noteIdsSet a
  // questo punto) da quelle aggiunte solo perché presenti nello snapshot di pubblicazione.
  const ownedNoteIds = new Set(noteIdsSet);

  const visiblePublishedFolders = publishedData.folders.filter(f => {
    if (f.visibility === 'public') return true;
    if (!isAuth) return false;
    if (f.visibility === 'private') return true;
    if (f.visibility === 'custom') return (f.allowedUsers || []).includes(currentUserEmail) || (f.allowedGroups || []).some(gId => userGroupIds.includes(gId));
    return false;
  });

  visiblePublishedFolders.forEach(f => {
    const iconTag = f.visibility === 'public' ? '🌍' : '🔒';
    if (folderIdsSet.has(f.id)) {
      const existingFolder = allFolders.find(folder => folder.id === f.id);
      if (existingFolder) { existingFolder.isPublished = true; existingFolder.icon = iconTag; }
    } else {
      allFolders.push({ id: f.id, parent_id: f.parent_id || '', icon: iconTag, title: f.title, isPublished: true });
      folderIdsSet.add(f.id);
    }
  });

  const visiblePublishedFolderIds = visiblePublishedFolders.map(f => f.id);
  const snapshotPublishedNoteIds = new Set(); // note aggiunte SOLO perché nello snapshot: se la query live sotto non le riconferma, vanno tolte
  publishedData.notes.filter(n => visiblePublishedFolderIds.includes(n.parent_id)).forEach(n => {
    if (!noteIdsSet.has(n.id)) {
      allNotes.push({ id: n.id, parent_id: n.parent_id, title: n.title, body: n.body, updated_time: n.updated_time, tags: ['Pubblicato'] });
      noteIdsSet.add(n.id);
      snapshotPublishedNoteIds.add(n.id);
    }
  });

  if (visiblePublishedFolderIds.length > 0) {
    // Lo snapshot in SQLite non viene mai invalidato quando una nota viene cancellata o spostata
    // fuori dal notebook pubblicato in Joplin — senza questo controllo, quella nota resterebbe
    // visibile come un fantasma nella webapp finché qualcuno non ripubblica esplicitamente il
    // notebook. La query live sotto conferma quali note dello snapshot esistono ancora davvero
    // nel notebook pubblicato; quelle non confermate vengono rimosse a fine funzione.
    const liveConfirmedNoteIds = new Set();
    let liveQuerySucceeded = false;
    try {
      const dbLiveResult = await pool.query(`SELECT jop_id, jop_parent_id, content FROM items WHERE jop_type = 1`);
      dbLiveResult.rows.forEach(row => {
        let parsed = {};
        try { parsed = JSON.parse(row.content.toString('utf-8')); } catch(e) { return; }
        if (Number(parsed.deleted_time || 0) > 0 || Number(parsed.is_conflict || 0) > 0) return;
        const effParent = row.jop_parent_id || parsed.parent_id || '';
        if (visiblePublishedFolderIds.includes(effParent)) {
          liveConfirmedNoteIds.add(row.jop_id);
          const freshNote = { id: row.jop_id, parent_id: effParent, title: parsed.title || 'Nuova Nota', body: parsed.body || '', updated_time: Number(parsed.user_updated_time || parsed.updated_time || 0), tags: ['Pubblicato'] };
          const existingIndex = allNotes.findIndex(n => n.id === row.jop_id);
          if (existingIndex >= 0) allNotes[existingIndex] = freshNote;
          else { allNotes.push(freshNote); noteIdsSet.add(row.jop_id); }
        }
      });
      liveQuerySucceeded = true;
    } catch (err) {
      console.error('/api/data (note pubblicate aggiornate live): errore nella query a Postgres:', err.message);
    }

    // Solo se la query live è andata a buon fine: senza questa condizione, un errore di Postgres
    // transitorio farebbe sparire TUTTE le note pubblicate invece di limitarsi a non aggiornarle.
    if (liveQuerySucceeded) {
      allNotes = allNotes.filter(n => {
        const isStaleSnapshotOnly = snapshotPublishedNoteIds.has(n.id) && !ownedNoteIds.has(n.id) && !liveConfirmedNoteIds.has(n.id);
        return !isStaleSnapshotOnly;
      });
    }
  }

  res.json({ folders: allFolders, notes: allNotes, isAuth });
});

app.get('/api/resource/:id', async (req, res) => {
  try {
    const result = await pool.query("SELECT name, content FROM items WHERE jop_id = $1 OR name LIKE $2", [req.params.id, '%' + req.params.id + '%']);
    let mimeType = 'application/octet-stream', fileName = req.params.id, binaryContent = null;
    for (let row of result.rows) {
      if (!row.content) continue;
      // Prima si decideva "è la riga di metadata" solo guardando se il primo carattere è "{":
      // un file binario che inizia per caso con quel byte veniva scambiato per JSON e i suoi
      // dati persi. Ora si prova un parse JSON completo: solo se ha successo e produce un
      // oggetto con i campi attesi lo trattiamo come metadata, altrimenti è contenuto binario.
      let parsedAsMetadata = false;
      try {
        const meta = JSON.parse(row.content.toString('utf-8'));
        if (meta && typeof meta === 'object' && (meta.mime || meta.title)) {
          if (meta.mime) mimeType = meta.mime;
          if (meta.title) fileName = meta.title;
          parsedAsMetadata = true;
        }
      } catch (e) { /* non è JSON valido: è la riga binaria */ }
      if (!parsedAsMetadata) binaryContent = row.content;
    }
    if (binaryContent) { res.setHeader('Content-Type', mimeType); if (!mimeType.startsWith('image/')) res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`); res.send(binaryContent); } 
    else { res.status(404).send('Not found'); }
  } catch (err) { res.status(500).send('Error'); }
});

app.listen(port, () => console.log(`🚀 Joplin Web Viewer su http://localhost:${port}`));
