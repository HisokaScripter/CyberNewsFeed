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
    if (event.key === 'Escape' && detailPanel.classList.contains('is-visible')) {
      closePanelAndClear();
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
    resetButton.addEventListener('click', () => {
      if (filters.search) {
        filters.search.value = '';
      }
      if (filters.source) {
        Array.from(filters.source.options).forEach((option) => {
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
    });
  }

  applyFilters();

})();
        