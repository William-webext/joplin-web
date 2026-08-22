const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.static('public'));
app.use(express.json()); // <-- AGGIUNTA: Necessario per leggere email e password inviati dal browser
// Diciamo al server di mostrare i file web contenuti nella cartella "public"
app.use(express.static('public'));
const port = 3000;

// Configura qui le credenziali del tuo PostgreSQL del Joplin Server
// Connessione PostgreSQL universale tramite Variabili d'Ambiente
const pool = new Pool({
  user: process.env.DB_USER || 'joplinuser',
  host: process.env.DB_HOST || 'db',
  database: process.env.DB_NAME || 'joplin',
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT || '5432', 10),
});

// Abilitiamo il CORS per poter interrogare le API dal browser
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});
// --- NUOVA API DI LOGIN ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Cerchiamo l'utente nel database tramite la sua email
    const result = await pool.query('SELECT id, password FROM users WHERE email = $1', [email]);
    
    // Se l'email non esiste
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Email non trovata' });
    }

    const user = result.rows[0];

    // 2. Confrontiamo la password inserita con l'Hash salvato nel DB da Joplin
    const isValid = await bcrypt.compare(password, user.password);

    // Se la password è sbagliata
    if (!isValid) {
      return res.status(401).json({ error: 'Password errata' });
    }

    // 3. Autenticazione riuscita! Restituiamo segretamente l'ID dell'utente al browser
    res.json({ success: true, userId: user.id });

  } catch (err) {
    console.error("Errore durante il login:", err);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});
// L'API principale: chiede le note di un utente specifico
// L'API principale: chiede le note, i taccuini e i TAG
// L'API principale: chiede le note, i taccuini e i TAG (inclusi quelli condivisi)
// L'API principale: chiede le note, i taccuini e i TAG (propri e condivisi)
app.get('/api/data/:owner_id', async (req, res) => {
  const ownerId = req.params.owner_id;
  
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

    const result = await pool.query(queryText, [ownerId]);

    const folders = [];
    const notes = [];
    const tags = [];
    const noteTags = [];

    result.rows.forEach(row => {
      let parsedContent = {};
      try {
        parsedContent = JSON.parse(row.content.toString('utf-8'));
      } catch (e) { return; }

      if (parsedContent.deleted_time && parsedContent.deleted_time > 0) return; 

      const effectiveParentId = row.jop_parent_id || parsedContent.parent_id || '';

      if (row.jop_type === 2) {
        let extractedIcon = '';
        if (parsedContent.icon) {
            try { extractedIcon = JSON.parse(parsedContent.icon).emoji || ''; } 
            catch (e) { extractedIcon = parsedContent.icon; }
        }
        folders.push({ 
          id: row.jop_id, 
          parent_id: effectiveParentId, 
          icon: extractedIcon, 
          title: parsedContent.title || 'Senza Titolo' 
        });
      } 
      else if (row.jop_type === 1) {
        notes.push({ 
          id: row.jop_id, 
          parent_id: effectiveParentId, 
          title: parsedContent.title || 'Nuova Nota', 
          body: parsedContent.body || '', 
          updated_time: Number(parsedContent.user_updated_time || parsedContent.updated_time || 0) 
        });
      }
      else if (row.jop_type === 5) {
        tags.push({ id: row.jop_id, title: parsedContent.title || 'Tag' });
      }
      else if (row.jop_type === 6) {
        noteTags.push({ note_id: parsedContent.note_id, tag_id: parsedContent.tag_id });
      }
    });

    notes.forEach(note => {
      const myTagIds = noteTags.filter(nt => nt.note_id === note.id).map(nt => nt.tag_id);
      note.tags = tags.filter(t => myTagIds.includes(t.id)).map(t => t.title);
    });

    res.json({ folders, notes });

  } catch (err) {
    console.error("Errore Database:", err);
    res.status(500).send('Errore di connessione al DB');
  }
});




// Nuova API per scoprire gli ID degli utenti
app.get('/api/users', async (req, res) => {
  try {
    // Leggiamo la tabella degli utenti (solo ID e email per privacy)
    const result = await pool.query('SELECT id, email FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error("Errore lettura utenti:", err);
    res.status(500).send('Errore di connessione al DB');
  }
});
// --- API DEFINITIVA E INDISTRUTTIBILE PER LE IMMAGINI ---
// --- API DEFINITIVA E INDISTRUTTIBILE PER LE IMMAGINI ---
// --- API UNIVERSALE PER IMMAGINI E ALLEGATI ---
app.get('/api/resource/:id', async (req, res) => {
  const resourceId = req.params.id;
  try {
    const result = await pool.query(
      "SELECT name, content FROM items WHERE jop_id = $1 OR name LIKE $2",
      [resourceId, '%' + resourceId + '%']
    );

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
        } else {
            binaryContent = row.content;
        }
    }

    if (binaryContent) {
      res.setHeader('Content-Type', mimeType);
      if (!mimeType.startsWith('image/')) {
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
      }
      res.send(binaryContent);
    } else {
      res.status(404).send('Risorsa non trovata');
    }
  } catch (err) {
    console.error("Errore API Risorse:", err);
    res.status(500).send('Errore interno del server');
  }
});

app.listen(port, () => {
  // Nuova API per scoprire gli ID degli utenti
  console.log(`🚀 Joplin Web Viewer Backend in esecuzione su http://localhost:${port}`);
});
