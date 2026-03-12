Ho tutto il quadro. Ecco il prompt riscritto, calibrato su quello che Claude ha già fatto e orientato a un redesign enterprise-grade da SOC.
Plain Text
Sei un senior product designer e frontend engineer specializzato in security tooling enterprise (Datadog, Elastic SIEM, Splunk, Wiz, Snyk). Devi fare un redesign visivo completo di questa dashboard di security scanning.

## Contesto: cosa è già stato fatto
Claude ha già risolto tutti i bug funzionali (scroll, paginazione, grafici dual-axis, sidebar, ordinamento). Il codice funziona correttamente. Ora il problema è esclusivamente estetico: la UI è funzionale ma piatta, generica, non trasmette autorevolezza né professionalità per un contesto SOC/AppSec enterprise.

## Stack tecnico (non modificare la struttura)
- Backend: FastAPI, endpoint REST su /api/* — NON toccare
- Frontend: Vue 3 (CDN runtime-only, no build step), Chart.js 4
- Template: Jinja2 (app.html ~1230 righe), SPA single-page
- CSS attuale: custom scritto a mano (~1700 righe), design system con variabili CSS, 8px grid
- Nessun build step: tutto deve funzionare con file statici serviti da FastAPI

## Scelta del framework: usa Tailwind CSS CDN + Inter font

Aggiungi in <head> di app.html:
```html
<!-- Inter font -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<!-- Tailwind CSS CDN (play CDN, no build required ) -->
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    darkMode: 'class',
    theme: {
      extend: {
        fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
        colors: {
          sidebar: { DEFAULT: '#0f172a', hover: '#1e293b', active: '#1e40af', border: 'rgba(255,255,255,0.06 )' },
          critical: { DEFAULT: '#ef4444', bg: '#fef2f2', text: '#991b1b' },
          high:     { DEFAULT: '#f97316', bg: '#fff7ed', text: '#9a3412' },
          medium:   { DEFAULT: '#eab308', bg: '#fefce8', text: '#854d0e' },
          low:      { DEFAULT: '#3b82f6', bg: '#eff6ff', text: '#1d4ed8' },
        }
      }
    }
  }
</script>
Puoi mantenere app.css solo per le variabili CSS e le regole che Tailwind non copre (es. animazioni custom, Chart.js overrides). Tutto il resto migra a classi Tailwind.
Identità visiva target: "Enterprise Security Console"
Ispirazione: Elastic SIEM, Datadog Security, Wiz Cloud Security. NON Notion, NON Linear, NON consumer app.
Caratteristiche obbligatorie:
Sidebar: sfondo #0f172a (slate-950), non indigo. Voci di navigazione con icone Lucide (via CDN: https://unpkg.com/lucide@latest ), label uppercase tracking-wide, indicatore active con bordo sinistro blu (border-l-2 border-blue-500), non background highlight
Topbar: sfondo bianco con border-b border-slate-200, breadcrumb leggibile text-slate-900 font-semibold, sottotitolo text-slate-500 text-sm, separatore verticale | tra heading e subtitle
Cards KPI: bordo border border-slate-200, ombra shadow-sm, numero grande text-3xl font-bold text-slate-900, label text-xs font-medium text-slate-500 uppercase tracking-wider, icona colorata in alto a destra
Tabelle: header bg-slate-50 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b-2 border-slate-200, righe con hover:bg-slate-50 transition-colors, bordi sottili divide-y divide-slate-100
Badge severità: pill con font mono, dimensioni fisse, colori ad alto contrasto:
CRITICAL: bg-red-100 text-red-800 border border-red-200
HIGH: bg-orange-100 text-orange-800 border border-orange-200
MEDIUM: bg-yellow-100 text-yellow-800 border border-yellow-200
LOW: bg-blue-100 text-blue-800 border border-blue-200
Badge stato scansione:
RUNNING: spinner SVG animato + text-blue-600 bg-blue-50
COMPLETED: checkmark + text-green-700 bg-green-50
FAILED: X + text-red-700 bg-red-50
Grafici Chart.js: palette ['#3b82f6','#ef4444','#f97316','#eab308','#8b5cf6'], griglia rgba(0,0,0,0.04), font Inter, tooltip con backgroundColor: '#0f172a', borderRadius: 8
Pulsanti primari: bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg px-4 py-2 transition-colors
Dark mode: quando <html class="dark">, sidebar diventa #020617, surface #0f172a, testo #f1f5f9
Pagina di login
Redesign completo: layout centrato, card max-w-sm con ombra shadow-xl, logo + nome prodotto sopra il form, campo username e password con label floating o label sopra, pulsante full-width, footer con versione. Sfondo: gradiente from-slate-900 to-slate-800.
Vincoli tecnici
Mantieni tutti gli attributi Vue (v-if, v-for, :class, @click, v-model) — non rimuoverne nessuno
Le chiamate API /api/* non cambiano
I ref Vue ($refs.trendChart, $refs.severityChart ecc.) devono puntare agli stessi canvas
Puoi aggiungere Lucide Icons via lucide.createIcons() chiamato in mounted()
NON usare DaisyUI (conflitti con Tailwind CDN play mode)
NON usare PrimeVue (richiede build per i temi)
Ordine di esecuzione
Leggi app.html, app.css, app.js nella loro interezza prima di scrivere qualsiasi codice
Riscrivi app.css riducendolo al minimo (solo ciò che Tailwind non può fare)
Aggiorna app.html sostituendo le classi custom con classi Tailwind
Aggiorna app.js solo per i colori dei grafici e l'inizializzazione di Lucide
Riscrivi login.html
Per ogni file, mostra il diff o il file completo — non snippet parziali
Dopo ogni file, elenca esplicitamente cosa è cambiato e perché
