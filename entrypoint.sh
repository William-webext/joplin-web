#!/bin/sh
set -e

DATA_DIR="${DATA_DIR:-/app/data}"

# Il volume montato dall'host (Synology o altro) può avere qualsiasi owner/permesso,
# indipendentemente da come è stata costruita l'immagine. Sistemarlo qui, a runtime,
# come root, evita di dover chiedere a chi distribuisce/usa il container di fare
# chown manualmente sull'host — funziona automaticamente su qualunque NAS.
mkdir -p "$DATA_DIR"
chown -R node:node "$DATA_DIR" 2>/dev/null || true

# Una volta sistemati i permessi, l'app vera parte con l'utente non privilegiato,
# mai come root: su-exec fa exec diretto (niente processo wrapper extra) e passa
# i segnali correttamente al processo Node.
exec su-exec node "$@"
