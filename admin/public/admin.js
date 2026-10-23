const strings = {
  en: {
    skip: 'Skip to reports', workspace: 'PRIVATE WORKSPACE', reports: 'Content reports', owner: 'Owner access',
    private: 'Private moderation inbox', administration: 'Administration / Reports', protected: 'Access protected', logout: 'Sign out',
    trust: 'TRUST & SAFETY', intro: 'Review what users chose to share. Track each report through resolution.', refresh: 'Refresh inbox',
    new: 'New', in_progress: 'In progress', processed: 'Processed', awaiting: 'Awaiting review', reviewing: 'Read, under review', completed: 'Review completed',
    countNote: 'Counts use the date and category filters, across all statuses.', inbox: 'Report inbox', newest: 'Newest first', category: 'Category', status: 'Status',
    allCategories: 'All categories', allStatuses: 'All statuses', harmful: 'Harmful', sexual: 'Sexual content', violence: 'Violence', deceptive: 'Deceptive', other: 'Other',
    from: 'From', to: 'Through', apply: 'Apply filters', reset: 'Reset', received: 'Received', reference: 'Report reference', review: 'Review', previous: 'Previous', next: 'Next',
    retention: 'Reports and moderation records expire automatically after 30 days. Processing never extends retention.', reportDetail: 'Report detail',
    loading: 'Loading reports…', indexing: 'Preparing the private inbox…', indexingHelp: 'The first index is still being built. Refresh shortly.',
    empty: 'All clear here', emptyHelp: 'No reports match these filters. New voluntary reports appear after synchronization.',
    error: 'The inbox could not be loaded.', tryAgain: 'Try again', unavailable: 'This report is no longer available. It may have expired or been removed.',
    session: 'Your session has ended. Reload to sign in again.', forbidden: 'This session is not authorized for the owner inbox.',
    limited: 'Too many requests. Please wait one minute.', changed: 'The inbox changed. The latest page has been loaded.',
    conflict: 'This report changed in another tab. Review its current status before trying again.', invalidDates: 'Choose a valid date range.',
    page: 'Page', shown: 'reports on this page', synced: 'Index synchronized', never: 'Waiting for synchronization', syncing: 'synchronization in progress',
    syncHelp: 'New submissions may take time to appear in Cloudflare KV.', timezone: 'Dates in',
    submitted: 'Voluntarily submitted content', notes: 'Optional note', noNotes: 'No note submitted.',
    literal: 'Submitted text is shown as plain text. Links, HTML and embedded instructions are never executed.',
    expires: 'Expires', firstRead: 'First marked read', processedAt: 'Processed', schema: 'Submission schema',
    workflow: 'Review workflow', unreadHelp: 'Opening a report does not mark it read. Start review explicitly.',
    progressHelp: 'Mark processed when you have finished reviewing this report.', processedHelp: 'Review complete. You can reopen it if further review is needed.',
    markRead: 'Mark read · start review', markProcessed: 'Mark processed', reopen: 'Reopen review', saving: 'Saving…', history: 'Recent status changes',
    invalidRecords: 'Some stored metadata could not be indexed. Investigate privately in Cloudflare; no content is logged.',
  },
  fr: {
    skip: 'Aller aux signalements', workspace: 'ESPACE PRIVÉ', reports: 'Signalements de contenu', owner: 'Accès propriétaire',
    private: 'Boîte de modération privée', administration: 'Administration / Signalements', protected: 'Accès protégé', logout: 'Déconnexion',
    trust: 'CONFIANCE ET SÉCURITÉ', intro: 'Examinez le contenu partagé volontairement et suivez chaque signalement.', refresh: 'Actualiser la boîte',
    new: 'Nouveaux', in_progress: 'En cours', processed: 'Traités', awaiting: 'À examiner', reviewing: 'Lus, en cours d’examen', completed: 'Examen terminé',
    countNote: 'Les compteurs respectent les filtres de date et de catégorie, tous statuts confondus.', inbox: 'Boîte de signalements', newest: 'Plus récents d’abord', category: 'Catégorie', status: 'Statut',
    allCategories: 'Toutes les catégories', allStatuses: 'Tous les statuts', harmful: 'Nuisible', sexual: 'Contenu sexuel', violence: 'Violence', deceptive: 'Trompeur', other: 'Autre',
    from: 'Du', to: 'Au inclus', apply: 'Appliquer', reset: 'Réinitialiser', received: 'Reçu le', reference: 'Référence', review: 'Examiner', previous: 'Précédente', next: 'Suivante',
    retention: 'Les signalements et leurs données de modération expirent après 30 jours. Leur traitement ne prolonge jamais ce délai.', reportDetail: 'Détail du signalement',
    loading: 'Chargement des signalements…', indexing: 'Préparation de la boîte privée…', indexingHelp: 'Le premier index est en cours de création. Actualisez dans un instant.',
    empty: 'Aucun signalement ici', emptyHelp: 'Aucun signalement ne correspond à ces filtres. Les nouveaux envois apparaissent après synchronisation.',
    error: 'Impossible de charger la boîte.', tryAgain: 'Réessayer', unavailable: 'Ce signalement n’est plus disponible. Il a peut-être expiré ou été supprimé.',
    session: 'Votre session a expiré. Rechargez la page pour vous reconnecter.', forbidden: 'Cette session n’est pas autorisée à consulter la boîte du propriétaire.',
    limited: 'Trop de requêtes. Patientez une minute.', changed: 'La boîte a changé. La première page a été actualisée.',
    conflict: 'Un autre onglet a modifié ce signalement. Vérifiez son statut avant de réessayer.', invalidDates: 'Choisissez une plage de dates valide.',
    page: 'Page', shown: 'signalements sur cette page', synced: 'Index synchronisé', never: 'En attente de synchronisation', syncing: 'synchronisation en cours',
    syncHelp: 'Les nouveaux envois peuvent mettre du temps à apparaître dans Cloudflare KV.', timezone: 'Dates affichées en',
    submitted: 'Contenu envoyé volontairement', notes: 'Note facultative', noNotes: 'Aucune note envoyée.',
    literal: 'Le texte est affiché sans interprétation. Les liens, le HTML et les instructions intégrées ne sont jamais exécutés.',
    expires: 'Expiration', firstRead: 'Première lecture explicite', processedAt: 'Traité le', schema: 'Schéma d’envoi',
    workflow: 'Suivi de l’examen', unreadHelp: 'Ouvrir un signalement ne le marque pas comme lu. Démarrez explicitement l’examen.',
    progressHelp: 'Marquez le signalement comme traité une fois son examen terminé.', processedHelp: 'Examen terminé. Vous pouvez le rouvrir si nécessaire.',
    markRead: 'Marquer lu · commencer', markProcessed: 'Marquer comme traité', reopen: 'Rouvrir l’examen', saving: 'Enregistrement…', history: 'Derniers changements de statut',
    invalidRecords: 'Certaines métadonnées n’ont pas pu être indexées. Vérifiez-les dans l’espace privé Cloudflare ; aucun contenu n’est journalisé.',
  },
};
const $ = id => document.getElementById(id);
let lang = navigator.language.startsWith('fr') ? 'fr' : 'en';
let data = null, selected = null, csrf = '', cursors = [''], next = null, filters = new URLSearchParams(), pending = 0, detailPending = 0, expiryTimer, reportTimer;
const controllers = new Set();
let serverClock = { time: Date.now(), monotonic: performance.now() };
const t = key => strings[lang][key] || key;
const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const format = (value, options = {}) => new Intl.DateTimeFormat(lang, { timeZone: zone, dateStyle: 'medium', timeStyle: 'short', ...options }).format(value);
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function alertMessage(message = '') { $('alert').textContent = message; $('alert').hidden = !message; }
function clearPrivate() {
  controllers.forEach(c => c.abort()); controllers.clear(); pending++; detailPending++;
  clearTimeout(reportTimer); clearTimeout(expiryTimer);
  data = null; selected = null; csrf = ''; next = null;
  $('rows').replaceChildren(); $('detail-content').replaceChildren();
  if ($('detail').open) $('detail').close();
  ['new', 'in_progress', 'processed'].forEach(s => $('count-' + s).textContent = '—');
  $('next').disabled = true; $('previous').disabled = true;
  $('refresh').disabled = false;
  $('state').replaceChildren(); $('page-label').textContent = ''; $('sync-label').textContent = '';
}
function fail(error) {
  if (error.name === 'AbortError') return;
  if ([401, 403].includes(error.status)) {
    clearPrivate(); alertMessage(t(error.status === 401 ? 'session' : 'forbidden')); return;
  }
  alertMessage(t(error.status === 429 ? 'limited' : error.status === 404 ? 'unavailable' : 'error'));
}
async function api(path, options = {}) {
  const controller = new AbortController(); controllers.add(controller);
  try {
    const response = await fetch(path, { cache: 'no-store', credentials: 'same-origin', redirect: 'error', ...options, signal: controller.signal });
    if (!response.headers.get('content-type')?.includes('application/json')) throw Object.assign(new Error(), { status: 401 });
    const body = await response.json();
    if (!response.ok) throw Object.assign(new Error(body.error), { status: response.status });
    if (Number.isFinite(body.server_time)) serverClock = { time: body.server_time, monotonic: performance.now() };
    return body;
  } finally { controllers.delete(controller); }
}
async function session() {
  const info = await api('/api/session'); csrf = info.csrf;
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(() => { clearPrivate(); alertMessage(t('session')); }, Math.max(0, info.expires - info.server_time));
}
function state(key, help, loading = false) {
  $('state').replaceChildren(...(loading ? [el('span', undefined, 'spinner'), el('br')] : []), el('strong', t(key)), ...(help ? [el('span', t(help))] : []));
}
function badge(value, status = false) { return el('span', t(value), 'badge' + (status ? ' status-' + value : '')); }
function scheduleExpiry() {
  clearTimeout(reportTimer);
  const deadlines = [...(data?.reports?.map(r => r.expires) || []), ...(selected ? [selected.report.expires] : [])];
  if (!deadlines.length) return;
  // Browsers overflow delays above ~24.8 days to 1 ms. Revalidate earlier
  // rather than accidentally creating a request loop for a 30-day report.
  const serverTime = serverClock.time + performance.now() - serverClock.monotonic;
  reportTimer = setTimeout(() => { clearPrivate(); void load(true); },
    Math.min(2147483647, Math.max(0, Math.min(...deadlines) - serverTime)));
}
function renderList() {
  $('rows').replaceChildren();
  if (!data) return;
  $('previous').disabled = cursors.length <= 1; $('next').disabled = !next;
  $('page-label').textContent = `${t('page')} ${cursors.length} · ${data.reports?.length || 0} ${t('shown')}`;
  if (!data.ready) { state('indexing', 'indexingHelp', true); return; }
  ['new', 'in_progress', 'processed'].forEach(s => $('count-' + s).textContent = new Intl.NumberFormat(lang).format(data.counts[s]));
  document.querySelectorAll('.stat').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.status === $('status').value)));
  $('sync-label').textContent = `${t('synced')} ${format(data.synchronized_at)}${data.syncing ? ' · ' + t('syncing') : ''}. ${t('syncHelp')}`;
  if (data.invalid_records) alertMessage(t('invalidRecords'));
  scheduleExpiry();
  if (!data.reports.length) { state('empty', 'emptyHelp'); return; }
  $('state').replaceChildren();
  for (const report of data.reports) {
    const tr = el('tr'), date = el('td', undefined, 'date');
    const dateText = el('time', new Intl.DateTimeFormat(lang, { timeZone: zone, dateStyle: 'medium' }).format(report.received));
    dateText.dateTime = new Date(report.received).toISOString();
    date.append(dateText, el('small', new Intl.DateTimeFormat(lang, { timeZone: zone, timeStyle: 'short' }).format(report.received)));
    const category = el('td'), status = el('td'), action = el('td');
    category.append(badge(report.category)); status.append(badge(report.status, true));
    const open = el('button', t('review') + ' →', 'review-button');
    open.setAttribute('aria-label', `${t('review')} ${report.id}`); open.addEventListener('click', () => openDetail(report.id)); action.append(open);
    const reference = el('td', report.id.slice(0, 8), 'reference'); reference.title = report.id;
    tr.append(date, category, reference, status, action); $('rows').append(tr);
  }
}
async function load(reset = false) {
  if (reset) cursors = [''];
  const generation = ++pending;
  $('rows').replaceChildren(); data = null; next = null;
  ['new', 'in_progress', 'processed'].forEach(s => $('count-' + s).textContent = '—');
  $('previous').disabled = true; $('next').disabled = true;
  state('loading', null, true); $('refresh').disabled = true; alertMessage();
  try {
    await session();
    const query = new URLSearchParams(filters); query.set('limit', '25');
    if (cursors.at(-1)) query.set('cursor', cursors.at(-1));
    const result = await api('/api/reports?' + query);
    if (generation !== pending) return;
    data = result; next = data.next_cursor; renderList();
  } catch (error) {
    if (generation !== pending) return;
    if (error.status === 409) { await load(true); alertMessage(t('changed')); return; }
    $('state').replaceChildren(); fail(error);
    if (![401, 403].includes(error.status)) {
      const retry = el('button', t('tryAgain'), 'secondary'); retry.addEventListener('click', () => load(true)); $('state').append(retry);
    }
  } finally { if (generation === pending) $('refresh').disabled = false; }
}
function meta(container, label, value) { container.append(el('dt', t(label)), el('dd', value)); }
function renderDetail() {
  if (!selected) return;
  const r = selected.report, root = $('detail-content'); root.replaceChildren();
  const badges = el('div', undefined, 'detail-badges'); badges.append(badge(r.category), badge(r.status, true));
  const metadata = el('dl', undefined, 'detail-meta');
  meta(metadata, 'reference', r.id); meta(metadata, 'received', format(r.received)); meta(metadata, 'expires', format(r.expires));
  meta(metadata, 'schema', String(r.schema_version));
  if (r.read_at) meta(metadata, 'firstRead', format(r.read_at));
  if (r.processed_at) meta(metadata, 'processedAt', format(r.processed_at));
  root.append(badges, metadata, el('h3', t('submitted'), 'detail-label'), el('pre', r.text, 'submitted'),
    el('p', t('literal'), 'detail-note'), el('h3', t('notes'), 'detail-label'), el('pre', r.details || t('noNotes'), 'submitted'));
  const workflow = el('section', undefined, 'workflow');
  workflow.append(el('h3', t('workflow'), 'detail-label'), el('p', t(r.status === 'new' ? 'unreadHelp' : r.status === 'in_progress' ? 'progressHelp' : 'processedHelp')));
  const button = el('button', t(r.status === 'new' ? 'markRead' : r.status === 'in_progress' ? 'markProcessed' : 'reopen'), 'primary');
  button.addEventListener('click', async () => {
    button.disabled = true; button.textContent = t('saving');
    const generation = detailPending;
    try {
      // Renew session/CSRF before writing; never keep a bearer token in JS.
      await session();
      await api('/api/reports/' + r.id, { method: 'PATCH', headers: { 'content-type': 'application/json', 'x-osia-csrf': csrf },
        body: JSON.stringify({ status: r.status === 'in_progress' ? 'processed' : 'in_progress', version: r.version }) });
      if (generation !== detailPending) return;
      await openDetail(r.id); await load(true);
    } catch (error) {
      if (generation !== detailPending) return;
      if (error.status === 409) { await openDetail(r.id); await load(true); alertMessage(t('conflict')); }
      else { fail(error); if ($('detail').open) { const note = el('p', t(error.status === 429 ? 'limited' : 'error'), 'alert'); note.setAttribute('role', 'alert'); workflow.append(note); } }
    } finally { button.disabled = false; button.textContent = t(r.status === 'new' ? 'markRead' : r.status === 'in_progress' ? 'markProcessed' : 'reopen'); }
  });
  workflow.append(button); root.append(workflow, el('p', t('retention'), 'detail-note'));
  if (selected.history.length) {
    const history = el('ul', undefined, 'history');
    selected.history.forEach(h => history.append(el('li', `${format(h.at)} · ${t(h.to_status)}`)));
    root.append(el('h3', t('history'), 'detail-label'), history);
  }
}
async function openDetail(id) {
  const generation = ++detailPending; selected = null;
  if (!$('detail').open) $('detail').showModal();
  $('detail-content').replaceChildren(el('p', t('loading')));
  try {
    const result = await api('/api/reports/' + id);
    if (generation !== detailPending || !$('detail').open) return;
    selected = result; renderDetail();
    scheduleExpiry();
  } catch (error) {
    if (generation !== detailPending) return;
    if ([401, 403].includes(error.status)) fail(error);
    else $('detail-content').replaceChildren(el('p', t(error.status === 404 ? 'unavailable' : error.status === 429 ? 'limited' : 'error'), 'alert'));
  }
}
function translate() {
  document.documentElement.lang = lang; document.title = `OSIA · ${t('reports')}`; $('language').value = lang;
  document.querySelectorAll('[data-i18n]').forEach(n => n.textContent = t(n.dataset.i18n));
  $('timezone').textContent = `${t('timezone')} ${zone}`; renderList(); renderDetail();
}
$('language').addEventListener('change', () => { lang = $('language').value; translate(); });
$('refresh').addEventListener('click', () => load(true));
$('filters').addEventListener('submit', event => {
  event.preventDefault(); const query = new URLSearchParams();
  for (const key of ['status', 'category']) if ($(key).value) query.set(key, $(key).value);
  for (const key of ['from', 'to']) {
    if (!$(key).value) continue;
    const [year, month, day] = $(key).value.split('-').map(Number);
    const date = new Date(year, month - 1, day + (key === 'to' ? 1 : 0));
    if (!Number.isFinite(date.valueOf())) { alertMessage(t('invalidDates')); return; }
    query.set(key, date.toISOString());
  }
  if (query.has('from') && query.has('to') && query.get('from') >= query.get('to')) { alertMessage(t('invalidDates')); return; }
  filters = query; void load(true);
});
$('filters').addEventListener('reset', () => { filters = new URLSearchParams(); void load(true); });
document.querySelectorAll('.stat').forEach(button => button.addEventListener('click', () => {
  $('status').value = button.dataset.status; $('filters').requestSubmit();
}));
$('next').addEventListener('click', () => { if (next) { cursors.push(next); void load(); } });
$('previous').addEventListener('click', () => { if (cursors.length > 1) { cursors.pop(); void load(); } });
$('close-detail').addEventListener('click', () => $('detail').close());
$('detail').addEventListener('close', () => { selected = null; detailPending++; $('detail-content').replaceChildren(); });
window.addEventListener('pagehide', clearPrivate);
window.addEventListener('pageshow', event => { if (event.persisted) { clearPrivate(); void load(true); } });
document.addEventListener('visibilitychange', () => { if (document.hidden) clearPrivate(); else void load(true); });
translate(); void load(true);
