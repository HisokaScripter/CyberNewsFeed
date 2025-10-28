(function() {
  const dataNode = document.getElementById('article-data');
  if (!dataNode) {
    return;
  }
  let articles = [];
  try {
    articles = JSON.parse(dataNode.textContent || '[]');
  } catch (error) {
    console.error('Unable to parse article payload:', error);
    return;
  }

  const cards = Array.from(document.querySelectorAll('.feed-card'));
  const cardColumn = document.querySelector('.card-column');
  const cardGroups = document.querySelector('.card-groups');
  const detailPanel = document.querySelector('.detail-panel');
  const lastSyncLabel = document.querySelector('[data-last-sync]');
  if (!detailPanel) {
    return;
  }
  const placeholder = detailPanel.querySelector('.detail-panel__placeholder');
  const content = detailPanel.querySelector('.detail-panel__content');
  const backdrop = detailPanel.querySelector('.detail-panel__backdrop');
  const closeControls = Array.from(detailPanel.querySelectorAll('[data-detail-close]'));
  const exportButton = document.querySelector('[data-action="export-view"]');
  const createViewButton = document.querySelector('[data-action="create-view"]');
  const helpButton = document.querySelector('[data-action="help-center"]');
  const profileButton = document.querySelector('[data-action="profile-menu"]');
  const profileMenu = document.getElementById('profile-menu');
  const helpPanel = document.getElementById('help-panel');
  const helpBackdrop = helpPanel ? helpPanel.querySelector('.help-panel__backdrop') : null;
  const helpCloseButtons = Array.from(document.querySelectorAll('[data-help-close]'));
  const helpQuickActionButtons = Array.from(document.querySelectorAll('[data-help-filter]'));
  const viewModal = document.getElementById('view-modal');
  const viewModalBackdrop = viewModal ? viewModal.querySelector('.modal__backdrop') : null;
  const viewModalCloseButtons = Array.from(document.querySelectorAll('[data-view-modal-close]'));
  const viewModalForm = document.getElementById('view-modal-form');
  const viewModalInput = document.getElementById('view-modal-name');
  const toastNode = document.getElementById('app-toast');
  const savedViewsList = document.querySelector('[data-saved-views]');
  const savedViewsEmpty = document.querySelector('[data-saved-empty]');

  const refs = {
    title: detailPanel.querySelector('[data-detail="title"]'),
    source: detailPanel.querySelector('[data-detail="source"]'),
    date: detailPanel.querySelector('[data-detail="date"]'),
    link: detailPanel.querySelector('[data-detail="article"]'),
    sourceList: detailPanel.querySelector('[data-detail="sources"]'),
    summary: detailPanel.querySelector('[data-detail="AI-Summary"]'),
    content: detailPanel.querySelector('[data-detail="content"]'),
    notes: detailPanel.querySelector('[data-detail="notes"]'),
    iocs: detailPanel.querySelector('[data-detail="iocs"]'),
    ttps: detailPanel.querySelector('[data-detail="TTPs"]'),
    actors: detailPanel.querySelector('[data-detail="ThreatActors"]'),
    cves: detailPanel.querySelector('[data-detail="CVEs"]')
  };

  let closeTimer = null;
  let toastTimer = null;
  let lastFocusedElement = null;
  let savedViews = [];
  const SAVED_VIEWS_STORAGE_KEY = 'cybernewsfeed:savedViews';

  function showDetailPanel() {
    if (closeTimer) {
      clearTimeout(closeTimer);
      closeTimer = null;
    }
    detailPanel.hidden = false;
    detailPanel.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => {
      detailPanel.classList.add('is-visible');
    });
  }

  function hideDetailPanel() {
    detailPanel.classList.remove('is-visible');
    detailPanel.setAttribute('aria-hidden', 'true');
    if (closeTimer) {
      clearTimeout(closeTimer);
    }
    closeTimer = window.setTimeout(() => {
      detailPanel.hidden = true;
      if (placeholder) {
        placeholder.style.display = '';
        placeholder.innerHTML = defaultPlaceholderHTML;
      }
      if (content) {
        content.hidden = true;
      }
      closeTimer = null;
    }, 320);
  }

  function storeFocusReference() {
    lastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  }

  function restoreFocusReference() {
    if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') {
      try {
        lastFocusedElement.focus({ preventScroll: true });
      } catch (error) {
        lastFocusedElement.focus();
      }
    }
    lastFocusedElement = null;
  }

  function showToast(message, type = 'info') {
    if (!toastNode) {
      return;
    }
    toastNode.textContent = message;
    if (type) {
      toastNode.setAttribute('data-toast-type', type);
    } else {
      toastNode.removeAttribute('data-toast-type');
    }
    toastNode.hidden = false;
    requestAnimationFrame(() => {
      toastNode.classList.add('is-visible');
    });
    if (toastTimer) {
      clearTimeout(toastTimer);
    }
    toastTimer = window.setTimeout(() => {
      toastNode.classList.remove('is-visible');
      toastTimer = window.setTimeout(() => {
        toastNode.hidden = true;
        toastNode.textContent = '';
        toastNode.removeAttribute('data-toast-type');
        toastTimer = null;
      }, 320);
    }, 2800);
  }

  function isHelpPanelOpen() {
    return Boolean(helpPanel && !helpPanel.hidden);
  }

  function openHelpPanel() {
    if (!helpPanel) {
      return;
    }
    storeFocusReference();
    helpPanel.hidden = false;
    helpPanel.setAttribute('aria-hidden', 'false');
    const focusable = helpPanel.querySelector('button, [href], input, select, textarea');
    if (focusable && typeof focusable.focus === 'function') {
      focusable.focus();
    }
  }

  function closeHelpPanel(options = {}) {
    if (!helpPanel) {
      return;
    }
    helpPanel.setAttribute('aria-hidden', 'true');
    helpPanel.hidden = true;
    if (!options.silent) {
      restoreFocusReference();
    }
  }

  function isViewModalOpen() {
    return Boolean(viewModal && !viewModal.hidden);
  }

  function openViewModal(defaultName = '') {
    if (!viewModal) {
      return;
    }
    storeFocusReference();
    viewModal.hidden = false;
    viewModal.setAttribute('aria-hidden', 'false');
    if (viewModalForm) {
      viewModalForm.reset();
    }
    if (viewModalInput) {
      viewModalInput.value = defaultName;
      viewModalInput.focus();
      viewModalInput.select();
    }
  }

  function closeViewModal(options = {}) {
    if (!viewModal) {
      return;
    }
    viewModal.setAttribute('aria-hidden', 'true');
    viewModal.hidden = true;
    if (viewModalForm) {
      viewModalForm.reset();
    }
    if (!options.silent) {
      restoreFocusReference();
    }
  }

  function isProfileMenuOpen() {
    return Boolean(profileMenu && !profileMenu.hidden);
  }

  function openProfileMenu() {
    if (!profileMenu || !profileButton) {
      return;
    }
    profileMenu.hidden = false;
    profileButton.setAttribute('aria-expanded', 'true');
    storeFocusReference();
    const firstItem = profileMenu.querySelector('button');
    if (firstItem && typeof firstItem.focus === 'function') {
      firstItem.focus();
    }
  }

  function closeProfileMenu(options = {}) {
    if (!profileMenu || !profileButton) {
      return;
    }
    profileMenu.hidden = true;
    profileButton.setAttribute('aria-expanded', 'false');
    if (!options.silent) {
      restoreFocusReference();
    }
  }

  function toggleProfileMenu() {
    if (isProfileMenuOpen()) {
      closeProfileMenu();
    } else {
      openProfileMenu();
    }
  }

  function generateViewId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    return `view-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function createDefaultViewName() {
    const now = new Date();
    try {
      return `View ${now.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })}`;
    } catch (error) {
      return `View ${now.getMonth() + 1}/${now.getDate()} ${now.getHours()}:${String(now.getMinutes()).padStart(2, '0')}`;
    }
  }

  function applyHelpQuickAction(action) {
    if (!action) {
      return;
    }
    const normalized = action.toLowerCase();
    if (normalized === 'reset') {
      resetFilters();
      closeHelpPanel({ silent: true });
      restoreFocusReference();
      return;
    }
    if (normalized === 'cves') {
      if (filters.cves) filters.cves.checked = true;
      if (filters.actors) filters.actors.checked = false;
      if (filters.iocs) filters.iocs.checked = false;
      if (filters.ttps) filters.ttps.checked = false;
      applyFilters();
      showToast('Filtered to items enriched with CVEs.', 'success');
    } else if (normalized === 'actors') {
      if (filters.actors) filters.actors.checked = true;
      if (filters.cves) filters.cves.checked = false;
      if (filters.iocs) filters.iocs.checked = false;
      if (filters.ttps) filters.ttps.checked = false;
      applyFilters();
      showToast('Highlighting items mentioning threat actors.', 'success');
    } else {
      return;
    }
    closeHelpPanel({ silent: true });
    restoreFocusReference();
  }

  function clearNode(node) {
    if (!node) {
      return;
    }
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function ensureArray(value) {
    if (Array.isArray(value)) {
      return value.filter((item) => item !== null && item !== undefined && item !== '');
    }
    if (value === null || value === undefined || value === '') {
      return [];
    }
    return [value];
  }

  function createPill(text) {
    const pill = document.createElement('span');
    pill.className = 'detail-panel__pill';
    pill.textContent = text;
    return pill;
  }

  function renderPills(container, values, emptyLabel) {
    if (!container) {
      return;
    }
    clearNode(container);
    const items = ensureArray(values);
    if (!items.length) {
      const empty = document.createElement('span');
      empty.className = 'detail-panel__empty';
      empty.textContent = emptyLabel;
      container.appendChild(empty);
      return;
    }
    items.forEach((item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        const pill = createPill(Object.values(item).join(' · '));
        container.appendChild(pill);
      } else {
        const pill = createPill(String(item));
        container.appendChild(pill);
      }
    });
  }

  function renderCves(container, values) {
    if (!container) {
      return;
    }
    clearNode(container);
    const items = ensureArray(values);
    if (!items.length) {
      const empty = document.createElement('li');
      empty.className = 'detail-panel__empty';
      empty.textContent = 'No CVEs reported.';
      container.appendChild(empty);
      return;
    }
    items.forEach((entry) => {
      const item = document.createElement('li');
      item.className = 'detail-panel__cve';
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        const id = document.createElement('div');
        id.className = 'detail-panel__cve-id';
        id.textContent = entry.cve || 'Unknown CVE';
        item.appendChild(id);

        const metaBits = [];
        if (entry.cvss || entry.cvss === 0) {
          metaBits.push(`CVSS ${entry.cvss}`);
        }
        if (typeof entry.exploited === 'boolean') {
          metaBits.push(entry.exploited ? 'Exploited' : 'Not confirmed exploited');
        }
        if (typeof entry.patch_available === 'boolean') {
          metaBits.push(entry.patch_available ? 'Patch available' : 'Patch unavailable');
        }
        if (entry.weaponization_stage) {
          metaBits.push(entry.weaponization_stage);
        }
        if (metaBits.length) {
          const meta = document.createElement('div');
          meta.className = 'detail-panel__cve-meta';
          meta.textContent = metaBits.join(' • ');
          item.appendChild(meta);
        }
        if (Array.isArray(entry.mapped_mitre_ids) && entry.mapped_mitre_ids.length) {
          const mitre = document.createElement('div');
          mitre.className = 'detail-panel__cve-mitre';
          mitre.textContent = `MITRE: ${entry.mapped_mitre_ids.join(', ')}`;
          item.appendChild(mitre);
        }
      } else {
        item.textContent = String(entry);
      }
      container.appendChild(item);
    });
  }

  function renderSources(container, values) {
    if (!container) {
      return;
    }
    clearNode(container);
    const items = Array.isArray(values) ? values : [];
    if (!items.length) {
      const empty = document.createElement('li');
      empty.className = 'detail-panel__source-item';
      empty.textContent = 'Source unavailable';
      container.appendChild(empty);
      return;
    }
    items.forEach((entry) => {
      if (!entry) {
        return;
      }
      const name = typeof entry === 'string' ? entry : entry.name;
      const link = typeof entry === 'object' && entry.url ? entry.url : '';
      if (!name) {
        return;
      }
      const item = document.createElement('li');
      item.className = 'detail-panel__source-item';
      if (link) {
        const anchor = document.createElement('a');
        anchor.href = link;
        anchor.target = '_blank';
        anchor.rel = 'noopener noreferrer';
        anchor.textContent = name;
        item.appendChild(anchor);
      } else {
        item.textContent = name;
      }
      container.appendChild(item);
    });
    if (!container.childElementCount) {
      const fallback = document.createElement('li');
      fallback.className = 'detail-panel__source-item';
      fallback.textContent = 'Source unavailable';
      container.appendChild(fallback);
    }
  }

  function renderRichText(container, value, fallback) {
    if (!container) {
      return;
    }
    clearNode(container);

    const segments = [];

    const pushSegment = (segment) => {
      if (segment === null || segment === undefined) {
        return;
      }
      const stringValue = String(segment).trim();
      if (!stringValue) {
        return;
      }
      stringValue.split(/\r?\n+/).forEach((part) => {
        const trimmed = part.trim();
        if (trimmed) {
          segments.push(trimmed);
        }
      });
    };

    if (Array.isArray(value)) {
      value.forEach((entry) => {
        if (entry && typeof entry === 'object' && 'text' in entry) {
          pushSegment(entry.text);
        } else {
          pushSegment(entry);
        }
      });
    } else if (value && typeof value === 'object') {
      if (typeof value.text === 'string') {
        pushSegment(value.text);
      }
      if (Array.isArray(value.paragraphs)) {
        value.paragraphs.forEach((paragraph) => pushSegment(paragraph));
      } else if (value.content) {
        pushSegment(value.content);
      } else {
        pushSegment(JSON.stringify(value));
      }
    } else if (value || value === 0) {
      pushSegment(value);
    }

    if (!segments.length) {
      const empty = document.createElement('p');
      empty.className = 'detail-panel__empty';
      empty.textContent = fallback;
      container.appendChild(empty);
      return;
    }

    segments.forEach((segment) => {
      const paragraph = document.createElement('p');
      paragraph.textContent = segment;
      container.appendChild(paragraph);
    });
  }

  function setText(node, value, fallback) {
    if (!node) {
      return;
    }
    const text = value === null || value === undefined || String(value).trim() === '' ? fallback : String(value);
    node.textContent = text;
  }

  function setFullText(node, value, fallback) {
    if (!node) {
      return;
    }
    if (value === null || value === undefined || String(value).trim() === '') {
      node.textContent = fallback;
    } else {
      node.textContent = String(value);
    }
  }

  function loadSavedViews() {
    if (typeof window === 'undefined' || !window.localStorage) {
      return [];
    }
    try {
      const raw = window.localStorage.getItem(SAVED_VIEWS_STORAGE_KEY);
      if (!raw) {
        return [];
      }
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed
        .map((entry) => (entry && typeof entry === 'object' ? entry : null))
        .filter((entry) => entry && typeof entry.id === 'string' && typeof entry.name === 'string' && entry.state)
        .map((entry) => ({
          id: entry.id,
          name: entry.name,
          createdAt: entry.createdAt || entry.savedAt || null,
          state: entry.state
        }));
    } catch (error) {
      console.warn('Unable to load saved views from storage.', error);
      return [];
    }
  }

  function persistSavedViews(list) {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    try {
      window.localStorage.setItem(SAVED_VIEWS_STORAGE_KEY, JSON.stringify(list));
    } catch (error) {
      console.warn('Unable to persist saved views.', error);
      showToast('Unable to persist saved views to storage.', 'warning');
    }
  }

  function renderSavedViews() {
    if (!savedViewsList) {
      return;
    }
    clearNode(savedViewsList);
    if (!savedViews.length) {
      if (savedViewsEmpty) {
        savedViewsEmpty.hidden = false;
        savedViewsList.appendChild(savedViewsEmpty);
      }
      return;
    }
    if (savedViewsEmpty) {
      savedViewsEmpty.hidden = true;
    }
    savedViews.forEach((view) => {
      const item = document.createElement('li');
      const wrapper = document.createElement('div');
      wrapper.className = 'saved-view';

      const applyButton = document.createElement('button');
      applyButton.type = 'button';
      applyButton.className = 'saved-view__apply';
      applyButton.setAttribute('data-saved-view', view.id);

      const nameNode = document.createElement('span');
      nameNode.textContent = view.name;
      applyButton.appendChild(nameNode);

      const meta = document.createElement('span');
      meta.className = 'saved-view__meta';
      const createdDate = parseDateValue(view.createdAt);
      if (createdDate) {
        meta.textContent = `Saved ${formatRelativeTime(createdDate)}`;
      } else {
        meta.textContent = 'Saved view';
      }
      applyButton.appendChild(meta);

      const removeButton = document.createElement('button');
      removeButton.type = 'button';
      removeButton.className = 'saved-view__remove';
      removeButton.setAttribute('data-saved-view-remove', view.id);
      removeButton.setAttribute('aria-label', `Remove saved view ${view.name}`);
      removeButton.textContent = '×';

      wrapper.appendChild(applyButton);
      wrapper.appendChild(removeButton);
      item.appendChild(wrapper);
      savedViewsList.appendChild(item);
    });
  }

  function gatherCurrentFilterState() {
    const categoryCheckboxes = filters.categories || [];
    const selectedCategories = categoryCheckboxes
      .filter((checkbox) => checkbox.checked)
      .map((checkbox) => checkbox.value);
    const limitedCategories = selectedCategories.length > 0 && selectedCategories.length < categoryCheckboxes.length;
    const selectedSources = Array.from(filters.source?.selectedOptions || [])
      .map((option) => option.value)
      .filter((value) => value);
    return {
      search: filters.search ? filters.search.value.trim() : '',
      sources: selectedSources,
      categories: {
        selected: selectedCategories,
        limited: limitedCategories
      },
      toggles: {
        cves: Boolean(filters.cves?.checked),
        actors: Boolean(filters.actors?.checked),
        iocs: Boolean(filters.iocs?.checked),
        ttps: Boolean(filters.ttps?.checked)
      }
    };
  }

  function applySavedView(view) {
    if (!view || !view.state) {
      return;
    }
    const state = view.state || {};
    if (filters.search) {
      filters.search.value = state.search || '';
    }
    if (filters.source) {
      const selectedSet = new Set(Array.isArray(state.sources) ? state.sources : []);
      Array.from(filters.source.options || []).forEach((option) => {
        option.selected = selectedSet.has(option.value);
      });
    }
    const categoryCheckboxes = filters.categories || [];
    const selectedCategories = new Set(Array.isArray(state.categories?.selected) ? state.categories.selected : []);
    const limited = Boolean(state.categories?.limited) && selectedCategories.size > 0;
    categoryCheckboxes.forEach((checkbox) => {
      if (!limited) {
        checkbox.checked = true;
      } else {
        checkbox.checked = selectedCategories.has(checkbox.value);
      }
    });
    if (filters.cves) filters.cves.checked = Boolean(state.toggles?.cves);
    if (filters.actors) filters.actors.checked = Boolean(state.toggles?.actors);
    if (filters.iocs) filters.iocs.checked = Boolean(state.toggles?.iocs);
    if (filters.ttps) filters.ttps.checked = Boolean(state.toggles?.ttps);
    applyFilters();
    showToast(`Applied view "${view.name}"`, 'success');
  }

  function removeSavedView(id) {
    const originalLength = savedViews.length;
    savedViews = savedViews.filter((view) => view.id !== id);
    if (savedViews.length !== originalLength) {
      persistSavedViews(savedViews);
      renderSavedViews();
      showToast('Saved view removed.', 'info');
    }
  }

  function upsertSavedView(name) {
    const trimmedName = name.trim();
    if (!trimmedName) {
      showToast('Please provide a name for the view.', 'warning');
      if (viewModalInput) {
        viewModalInput.focus();
      }
      return;
    }
    const nextState = gatherCurrentFilterState();
    const existingIndex = savedViews.findIndex((entry) => entry.name.toLowerCase() === trimmedName.toLowerCase());
    const nowIso = new Date().toISOString();
    if (existingIndex >= 0) {
      savedViews[existingIndex] = {
        ...savedViews[existingIndex],
        name: trimmedName,
        createdAt: nowIso,
        state: nextState
      };
      showToast(`Updated view "${trimmedName}"`, 'success');
    } else {
      savedViews.push({
        id: generateViewId(),
        name: trimmedName,
        createdAt: nowIso,
        state: nextState
      });
      showToast(`Saved view "${trimmedName}" created.`, 'success');
    }
    savedViews.sort((a, b) => {
      const aDate = parseDateValue(a.createdAt);
      const bDate = parseDateValue(b.createdAt);
      const aTime = aDate ? aDate.getTime() : 0;
      const bTime = bDate ? bDate.getTime() : 0;
      return bTime - aTime;
    });
    persistSavedViews(savedViews);
    renderSavedViews();
  }

  function handleViewModalSubmit(event) {
    event.preventDefault();
    const name = viewModalInput ? viewModalInput.value : '';
    upsertSavedView(name || '');
    closeViewModal({ silent: true });
    restoreFocusReference();
  }

  function handleProfileMenuAction(action) {
    if (!action) {
      return;
    }
    const normalized = action.toLowerCase();
    let message = '';
    let tone = 'info';
    if (normalized === 'profile') {
      message = 'Profile insights coming soon.';
    } else if (normalized === 'settings') {
      message = 'Account settings are not available in this offline preview.';
    } else if (normalized === 'signout') {
      message = 'Sign out is disabled in the static demo.';
      tone = 'warning';
    } else {
      return;
    }
    closeProfileMenu({ silent: true });
    restoreFocusReference();
    showToast(message, tone);
  }

  function updateDetail(article) {
    if (!article) {
      return;
    }
    if (placeholder) {
      placeholder.style.display = 'none';
    }
    if (content) {
      content.hidden = false;
    }
    const sourceEntries = Array.isArray(article.sources) ? article.sources : [];
    const sourceNames = sourceEntries
      .map((entry) => {
        if (!entry) {
          return '';
        }
        if (typeof entry === 'string') {
          return entry;
        }
        return entry.name || '';
      })
      .filter((name) => name);
    const primarySource = sourceNames.length ? sourceNames.join(', ') : (article.source || '');
    setText(refs.title, article.title || '', 'Untitled');
    setText(refs.source, primarySource || 'Unknown source', 'Unknown source');
    renderSources(refs.sourceList, sourceEntries);
    setText(refs.date, article.date || '', 'Date unavailable');
    if (refs.link) {
      const href = article.article || (sourceEntries.find((entry) => entry && entry.url)?.url) || '';
      if (href) {
        refs.link.href = href;
        refs.link.classList.remove('is-disabled');
        refs.link.textContent = 'Open original article';
      } else {
        refs.link.removeAttribute('href');
        refs.link.classList.add('is-disabled');
        refs.link.textContent = 'Link unavailable';
      }
    }
    setFullText(refs.summary, article['AI-Summary'], 'No AI summary available.');
    setFullText(refs.notes, article.notes, 'No analyst notes provided.');
    renderPills(refs.actors, article.ThreatActors, 'No threat actors identified.');
    renderPills(refs.ttps, article.TTPs, 'No tactics or techniques listed.');
    renderPills(refs.iocs, article.iocs, 'No indicators extracted.');
    renderCves(refs.cves, article.CVEs);
    const contentValue = article.content ?? article.contents ?? article.body ?? '';
    renderRichText(refs.content, contentValue, 'No additional content available.');
  }


  let activeCard = null;

  function clearActiveCard() {
    if (activeCard) {
      activeCard.classList.remove('feed-card--active');
      activeCard = null;
    }
  }
  const countLabel = document.querySelector('[data-count-label]') || document.querySelector('.card-column__count');
  const categorySections = Array.from(document.querySelectorAll('[data-category-section]'));
  const filterPanel = document.getElementById('feed-filter-panel');
  if (filterPanel) {
    filterPanel.addEventListener('submit', (event) => event.preventDefault());
  }
  const filters = {
    search: document.getElementById('filter-search'),
    source: document.getElementById('filter-source'),
    categories: Array.from(document.querySelectorAll('input[name="category"]')),
    cves: document.getElementById('filter-has-cves'),
    actors: document.getElementById('filter-has-actors'),
    iocs: document.getElementById('filter-has-iocs'),
    ttps: document.getElementById('filter-has-ttps')
  };
  const resetButton = document.getElementById('filter-reset');
  const defaultPlaceholderHTML = placeholder ? placeholder.innerHTML : '';

  function parseDateValue(raw) {
    if (!raw && raw !== 0) {
      return null;
    }
    if (raw instanceof Date && !Number.isNaN(raw.getTime())) {
      return raw;
    }
    if (typeof raw === 'number' && Number.isFinite(raw)) {
      const fromNumber = new Date(raw);
      return Number.isNaN(fromNumber.getTime()) ? null : fromNumber;
    }
    const stringValue = String(raw).trim();
    if (!stringValue) {
      return null;
    }
    const parsed = new Date(stringValue);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function formatRelativeTime(date) {
    if (!date) {
      return 'Awaiting data';
    }
    const now = new Date();
    const diffMs = Math.max(0, now.getTime() - date.getTime());
    const minute = 60 * 1000;
    const hour = 60 * minute;
    const day = 24 * hour;
    if (diffMs < minute) {
      return 'Just now';
    }
    if (diffMs < hour) {
      const minutes = Math.round(diffMs / minute);
      return `${minutes} min${minutes === 1 ? '' : 's'} ago`;
    }
    if (diffMs < day) {
      const hours = Math.round(diffMs / hour);
      return `${hours} hr${hours === 1 ? '' : 's'} ago`;
    }
    const days = Math.round(diffMs / day);
    if (days <= 7) {
      return `${days} day${days === 1 ? '' : 's'} ago`;
    }
    return date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  function updateLastSyncDisplay() {
    if (!lastSyncLabel) {
      return;
    }
    if (!articles.length) {
      lastSyncLabel.textContent = 'Awaiting data';
      lastSyncLabel.classList.add('is-muted');
      lastSyncLabel.removeAttribute('title');
      return;
    }

    let newest = null;
    let fallbackLabel = '';
    const candidateKeys = ['updated_at', 'updated', 'last_seen', 'date', 'published_at', 'published'];
    articles.forEach((article) => {
      if (!article || typeof article !== 'object') {
        return;
      }
      for (const key of candidateKeys) {
        if (!(key in article)) {
          continue;
        }
        const raw = article[key];
        const parsed = parseDateValue(raw);
        if (parsed) {
          if (!newest || parsed > newest) {
            newest = parsed;
          }
        } else if (!fallbackLabel && raw) {
          const stringValue = String(raw).trim();
          if (stringValue) {
            fallbackLabel = stringValue;
          }
        }
      }
    });

    if (!newest) {
      if (fallbackLabel) {
        lastSyncLabel.textContent = fallbackLabel;
        lastSyncLabel.classList.remove('is-muted');
        lastSyncLabel.removeAttribute('title');
      } else {
        lastSyncLabel.textContent = 'Awaiting data';
        lastSyncLabel.classList.add('is-muted');
        lastSyncLabel.removeAttribute('title');
      }
      return;
    }

    lastSyncLabel.textContent = formatRelativeTime(newest);
    lastSyncLabel.title = newest.toLocaleString();
    lastSyncLabel.classList.remove('is-muted');
  }

  let layoutFrame = null;

  function updateLayoutMetrics() {
    if (!cardColumn) {
      return;
    }
    const rect = cardColumn.getBoundingClientRect();
    const styles = window.getComputedStyle(cardColumn);
    const paddingBottom = parseFloat(styles.paddingBottom || '0');
    const gap = parseFloat(styles.gap || '0');
    const headerHeight = (cardColumn.querySelector('.card-column__header')?.offsetHeight) || 0;
    const filterHeight = filterPanel?.offsetHeight || 0;
    const viewportHeight = window.innerHeight;
    const baseHeight = Math.max(viewportHeight - rect.top - paddingBottom - 16, 360);
    const groupsHeight = Math.max(baseHeight - headerHeight - filterHeight - gap, 260);
    cardColumn.style.setProperty('--card-column-height', `${baseHeight}px`);
    cardColumn.style.setProperty('--card-groups-height', `${groupsHeight}px`);
  }

  function queueLayoutMetrics() {
    if (layoutFrame) {
      cancelAnimationFrame(layoutFrame);
    }
    layoutFrame = requestAnimationFrame(() => {
      layoutFrame = null;
      updateLayoutMetrics();
    });
  }

  updateLastSyncDisplay();
  queueLayoutMetrics();
  window.addEventListener('resize', queueLayoutMetrics);
  window.addEventListener('orientationchange', queueLayoutMetrics);
  window.addEventListener('load', queueLayoutMetrics);

  if (typeof ResizeObserver !== 'undefined' && cardColumn) {
    const observer = new ResizeObserver(() => queueLayoutMetrics());
    observer.observe(cardColumn);
    if (filterPanel) {
      observer.observe(filterPanel);
    }
    const columnHeader = cardColumn.querySelector('.card-column__header');
    if (columnHeader) {
      observer.observe(columnHeader);
    }
  }

  function closePanelAndClear() {
    hideDetailPanel();
    clearActiveCard();
  }

  closeControls.forEach((control) => {
    control.addEventListener('click', (event) => {
      event.preventDefault();
      closePanelAndClear();
    });
  });

  if (detailPanel) {
    detailPanel.addEventListener('click', (event) => {
      if (event.target === detailPanel || event.target === backdrop) {
        closePanelAndClear();
      }
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') {
      return;
    }
    let handled = false;
    if (isViewModalOpen()) {
      closeViewModal();
      handled = true;
    }
    if (isHelpPanelOpen()) {
      closeHelpPanel();
      handled = true;
    }
    if (isProfileMenuOpen()) {
      closeProfileMenu();
      handled = true;
    }
    if (detailPanel.classList.contains('is-visible')) {
      closePanelAndClear();
      handled = true;
    }
    if (handled) {
      event.preventDefault();
      event.stopPropagation();
    }
  });

  if (cardGroups) {
    cardGroups.addEventListener('wheel', (event) => {
      if (event.defaultPrevented) {
        return;
      }
      if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) {
        return;
      }
      cardGroups.scrollBy({ left: event.deltaY, behavior: 'auto' });
      event.preventDefault();
    }, { passive: false });
  }

  function focusCard(card, options = {}) {
    if (!card) {
      return;
    }
    const behavior = options.behavior || 'smooth';
    const columnList = card.closest('.card-list');
    if (columnList) {
      const targetTop = card.offsetTop - (columnList.clientHeight / 2) + (card.clientHeight / 2);
      const clampedTop = Number.isFinite(targetTop) ? Math.max(0, targetTop) : 0;
      if (typeof columnList.scrollTo === 'function') {
        columnList.scrollTo({ top: clampedTop, behavior });
      } else {
        columnList.scrollTop = clampedTop;
      }
    }
    if (cardGroups) {
      const column = card.closest('.card-category');
      if (column) {
        const columnLeft = column.offsetLeft;
        const columnWidth = column.offsetWidth;
        const viewportWidth = cardGroups.clientWidth || 1;
        const maxScroll = Math.max(0, cardGroups.scrollWidth - viewportWidth);
        let desiredLeft = columnLeft - (viewportWidth - columnWidth) / 2;
        if (!Number.isFinite(desiredLeft)) {
          desiredLeft = columnLeft;
        }
        desiredLeft = Math.min(Math.max(0, desiredLeft), maxScroll);
        if (typeof cardGroups.scrollTo === 'function') {
          cardGroups.scrollTo({ left: desiredLeft, behavior });
        } else {
          cardGroups.scrollLeft = desiredLeft;
        }
      }
    }
  }

  function selectCard(card) {
    if (!card || card.hidden) {
      return;
    }
    if (card === activeCard && detailPanel.classList.contains('is-visible')) {
      return;
    }
    clearActiveCard();
    activeCard = card;
    activeCard.classList.add('feed-card--active');
    focusCard(activeCard);
    const index = Number(card.getAttribute('data-index'));
    const article = Number.isFinite(index) ? articles[index] : null;
    showDetailPanel();
    if (placeholder) {
      placeholder.style.display = 'none';
      placeholder.innerHTML = defaultPlaceholderHTML;
    }
    if (content) {
      content.hidden = false;
      if (typeof content.scrollTo === 'function') {
        content.scrollTo({ top: 0, behavior: 'smooth' });
      } else {
        content.scrollTop = 0;
      }
    }
    updateDetail(article);
  }

  function getVisibleArticles() {
    return cards
      .filter((card) => !card.hidden)
      .map((card) => Number(card.getAttribute('data-index')))
      .filter((index) => Number.isFinite(index) && index >= 0 && index < articles.length)
      .map((index) => articles[index]);
  }

  function exportVisibleArticles() {
    const visibleArticles = getVisibleArticles();
    if (!visibleArticles.length) {
      showToast('No items available to export.', 'warning');
      return;
    }
    try {
      const payload = JSON.stringify(visibleArticles, null, 2);
      const blob = new Blob([payload], { type: 'application/json' });
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `cybersignal-view-${timestamp}.json`;
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.setTimeout(() => {
        URL.revokeObjectURL(link.href);
      }, 1000);
      showToast(`Exported ${visibleArticles.length} item${visibleArticles.length === 1 ? '' : 's'}.`, 'success');
    } catch (error) {
      console.error('Unable to export current view.', error);
      showToast('Unable to export current view.', 'error');
    }
  }

  function parseTokens(value) {
    if (!value) {
      return [];
    }
    const matches = value.match(/"[^"]+"|\S+/g) || [];
    return matches.map((token) => token.replace(/^"|"$/g, ''));
  }

  function matchesSearch(card, tokens) {
    if (!tokens.length) {
      return true;
    }
    const searchField = (card.dataset.search || '').toLowerCase();
    const datasetSources = (card.dataset.source || '')
      .split('|')
      .map((token) => token.trim())
      .filter((token) => token);
    const sourceField = datasetSources.join(' ').toLowerCase();
    const categoryLabels = (card.dataset.categoryLabels || '').toLowerCase();
    const categorySlugs = (card.dataset.categories || '').toLowerCase();
    const tagsField = (card.dataset.tags || '').toLowerCase();

    return tokens.every((rawToken) => {
      const token = rawToken.toLowerCase();
      if (!token) {
        return true;
      }
      if (token.startsWith('source:')) {
        const query = token.slice(7).trim();
        if (!query) {
          return true;
        }
        const lowered = query.toLowerCase();
        return datasetSources.some((sourceName) => sourceName.toLowerCase().includes(lowered));
      }
      if (token.startsWith('category:')) {
        const query = token.slice(9).trim();
        if (!query) {
          return true;
        }
        const slugMatches = categorySlugs.split(' ').filter(Boolean);
        return slugMatches.includes(query) || categoryLabels.includes(query);
      }
      if (token.startsWith('tag:')) {
        const query = token.slice(4).trim();
        return !query || tagsField.includes(query);
      }
      return searchField.includes(token);
    });
  }

  function applyFilters() {
    const categoryCheckboxes = filters.categories || [];
    const activeCategoryValues = categoryCheckboxes
      .filter((checkbox) => checkbox.checked)
      .map((checkbox) => checkbox.value);
    const shouldFilterByCategory = activeCategoryValues.length > 0 && activeCategoryValues.length < categoryCheckboxes.length;
    const selectedSources = Array.from(filters.source?.selectedOptions || [])
      .map((option) => option.value)
      .filter((value) => value);
    const tokens = parseTokens(filters.search?.value.trim() || '');
    const requireCves = Boolean(filters.cves?.checked);
    const requireActors = Boolean(filters.actors?.checked);
    const requireIocs = Boolean(filters.iocs?.checked);
    const requireTtps = Boolean(filters.ttps?.checked);

    let visibleCount = 0;
    let firstVisibleCard = null;

    cards.forEach((card) => {
      const dataset = card.dataset || {};
      const categories = (dataset.categories || '').split(' ').filter(Boolean);
      const datasetSources = (dataset.source || '')
        .split('|')
        .map((value) => value.trim())
        .filter((value) => value);
      const hasCategory = !shouldFilterByCategory || categories.some((value) => activeCategoryValues.includes(value));
      const matchesSource = !selectedSources.length || datasetSources.some((value) => selectedSources.includes(value));
      const hasCves = dataset.hasCves === 'true';
      const hasActors = dataset.hasActors === 'true';
      const hasIocs = dataset.hasIocs === 'true';
      const hasTtps = dataset.hasTtps === 'true';
      const searchMatch = matchesSearch(card, tokens);

      let visible = hasCategory && matchesSource && searchMatch;
      if (requireCves && !hasCves) visible = false;
      if (requireActors && !hasActors) visible = false;
      if (requireIocs && !hasIocs) visible = false;
      if (requireTtps && !hasTtps) visible = false;

      card.hidden = !visible;

      if (visible) {
        visibleCount += 1;
        if (!firstVisibleCard) {
          firstVisibleCard = card;
        }
      }
    });

    categorySections.forEach((section) => {
      const visibleCards = Array.from(section.querySelectorAll('.feed-card')).filter((card) => !card.hidden);
      const visibleInSection = visibleCards.length;
      const countNode = section.querySelector('.card-category__count');
      if (countNode) {
        countNode.textContent = `${visibleInSection} item${visibleInSection === 1 ? '' : 's'}`;
      }
      section.hidden = visibleInSection === 0;
    });

    if (countLabel) {
      countLabel.textContent = `${visibleCount} item${visibleCount === 1 ? '' : 's'}`;
    }

    if (visibleCount === 0) {
      closePanelAndClear();
      return;
    }

    if (placeholder) {
      placeholder.innerHTML = defaultPlaceholderHTML;
      placeholder.style.display = 'none';
    }

    if (activeCard && activeCard.hidden) {
      clearActiveCard();
    }

    if (!activeCard && firstVisibleCard) {
      selectCard(firstVisibleCard);
    } else if (activeCard) {
      focusCard(activeCard);
    }

    queueLayoutMetrics();
  }

  function resetFilters(options = {}) {
    const { silent = false } = options;
    if (filters.search) {
      filters.search.value = '';
    }
    if (filters.source) {
      Array.from(filters.source.options || []).forEach((option) => {
        option.selected = false;
      });
    }
    (filters.categories || []).forEach((checkbox) => {
      checkbox.checked = true;
    });
    if (filters.cves) filters.cves.checked = false;
    if (filters.actors) filters.actors.checked = false;
    if (filters.iocs) filters.iocs.checked = false;
    if (filters.ttps) filters.ttps.checked = false;
    applyFilters();
    if (!silent) {
      showToast('Filters reset.', 'info');
    }
  }

  cards.forEach((card) => {
    card.addEventListener('click', () => selectCard(card));
    card.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectCard(card);
      }
    });
  });

  const filterInputs = [
    filters.search,
    filters.source,
    filters.cves,
    filters.actors,
    filters.iocs,
    filters.ttps,
    ...(filters.categories || [])
  ].filter(Boolean);

  filterInputs.forEach((input) => {
    const eventName = input === filters.search ? 'input' : 'change';
    input.addEventListener(eventName, () => applyFilters());
  });

  if (resetButton) {
    resetButton.addEventListener('click', () => resetFilters());
  }

  if (exportButton) {
    exportButton.addEventListener('click', () => exportVisibleArticles());
  }

  if (helpButton) {
    helpButton.addEventListener('click', (event) => {
      event.preventDefault();
      if (isHelpPanelOpen()) {
        closeHelpPanel();
        return;
      }
      if (isProfileMenuOpen()) {
        closeProfileMenu({ silent: true });
        lastFocusedElement = helpButton;
      }
      openHelpPanel();
    });
  }

  helpCloseButtons.forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      closeHelpPanel();
    });
  });

  if (helpBackdrop) {
    helpBackdrop.addEventListener('click', () => closeHelpPanel());
  }

  helpQuickActionButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const action = button.getAttribute('data-help-filter');
      applyHelpQuickAction(action);
    });
  });

  if (profileButton) {
    profileButton.addEventListener('click', (event) => {
      event.preventDefault();
      if (isProfileMenuOpen()) {
        closeProfileMenu();
      } else {
        if (isHelpPanelOpen()) {
          closeHelpPanel({ silent: true });
        }
        toggleProfileMenu();
      }
    });
  }

  if (profileMenu) {
    profileMenu.addEventListener('click', (event) => {
      const actionTarget = event.target.closest('[data-menu-action]');
      if (!actionTarget) {
        return;
      }
      event.preventDefault();
      handleProfileMenuAction(actionTarget.getAttribute('data-menu-action'));
    });
  }

  document.addEventListener('click', (event) => {
    if (!isProfileMenuOpen()) {
      return;
    }
    if (!profileMenu || !profileButton) {
      return;
    }
    const target = event.target;
    if (profileMenu.contains(target)) {
      return;
    }
    if (profileButton === target || profileButton.contains(target)) {
      return;
    }
    closeProfileMenu({ silent: true });
    lastFocusedElement = null;
  });

  if (createViewButton) {
    createViewButton.addEventListener('click', (event) => {
      event.preventDefault();
      if (isHelpPanelOpen()) {
        closeHelpPanel({ silent: true });
        lastFocusedElement = createViewButton;
      }
      if (isProfileMenuOpen()) {
        closeProfileMenu({ silent: true });
      }
      openViewModal(createDefaultViewName());
    });
  }

  viewModalCloseButtons.forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      closeViewModal();
    });
  });

  if (viewModalBackdrop) {
    viewModalBackdrop.addEventListener('click', () => closeViewModal());
  }

  if (viewModalForm) {
    viewModalForm.addEventListener('submit', handleViewModalSubmit);
  }

  savedViews = loadSavedViews();
  renderSavedViews();

  if (savedViewsList) {
    savedViewsList.addEventListener('click', (event) => {
      const removeTarget = event.target.closest('[data-saved-view-remove]');
      if (removeTarget) {
        event.preventDefault();
        const id = removeTarget.getAttribute('data-saved-view-remove');
        if (id) {
          removeSavedView(id);
        }
        return;
      }
      const applyTarget = event.target.closest('[data-saved-view]');
      if (applyTarget) {
        const id = applyTarget.getAttribute('data-saved-view');
        const view = savedViews.find((entry) => entry.id === id);
        if (view) {
          applySavedView(view);
        }
      }
    });
  }

  applyFilters();

})();
        