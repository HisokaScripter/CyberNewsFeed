(function () {
  const dataNode = document.getElementById('article-data');
  if (!dataNode) {
    return;
  }

  let articles = [];
  try {
    const payload = JSON.parse(dataNode.textContent || '[]');
    if (Array.isArray(payload)) {
      articles = payload.filter((item) => item && typeof item === 'object');
    }
  } catch (error) {
    console.error('Unable to parse article payload:', error);
    return;
  }

  const board = document.querySelector('[data-category-board]');
  const emptyState = board ? board.querySelector('[data-board-empty]') : null;
  const totalCountLabel = document.querySelector('[data-total-count]');
  const lastSyncLabel = document.querySelector('[data-last-sync]');
  const drawer = document.querySelector('[data-detail-panel]');
  const drawerSurface = drawer ? drawer.querySelector('.drawer__surface') : null;
  const closeControls = drawer ? Array.from(drawer.querySelectorAll('[data-drawer-close]')) : [];
  const filterToggle = document.querySelector('[data-filter-toggle]');
  const filterToggleLabel = filterToggle ? filterToggle.querySelector('[data-filter-toggle-label]') : null;
  const filterPanel = document.querySelector('[data-filter-panel]');
  const filterSurface = filterPanel ? filterPanel.querySelector('.filter-panel__surface') : null;
  const filterCloseControls = filterPanel ? Array.from(filterPanel.querySelectorAll('[data-filter-close]')) : [];
  const filterTextInput = filterPanel ? filterPanel.querySelector('[data-filter-text]') : null;
  const categoryListNode = filterPanel ? filterPanel.querySelector('[data-filter-category-list]') : null;
  const sourceListNode = filterPanel ? filterPanel.querySelector('[data-filter-source-list]') : null;
  const enrichmentFlags = filterPanel ? Array.from(filterPanel.querySelectorAll('[data-filter-flag]')) : [];
  const clearFiltersButton = filterPanel ? filterPanel.querySelector('[data-filter-clear]') : null;
  const applyFiltersButton = filterPanel ? filterPanel.querySelector('[data-filter-apply]') : null;

  if (!board || !drawer || !drawerSurface) {
    return;
  }

  const detailRefs = {
    categories: drawer.querySelector('[data-detail="categories"]'),
    title: drawer.querySelector('[data-detail="title"]'),
    source: drawer.querySelector('[data-detail="source"]'),
    date: drawer.querySelector('[data-detail="date"]'),
    link: drawer.querySelector('[data-detail="link"]'),
    summary: drawer.querySelector('[data-detail="AI-Summary"]'),
    notes: drawer.querySelector('[data-detail="notes"]'),
    ThreatActors: drawer.querySelector('[data-detail="ThreatActors"]'),
    TTPs: drawer.querySelector('[data-detail="TTPs"]'),
    iocs: drawer.querySelector('[data-detail="iocs"]'),
    CVEs: drawer.querySelector('[data-detail="CVEs"]'),
  };

  const sectionNodes = new Map();
  Array.from(drawer.querySelectorAll('[data-section]')).forEach((section) => {
    const key = section.getAttribute('data-section');
    if (key) {
      sectionNodes.set(key, section);
    }
  });

  let activeArticle = null;
  let lastFocusedElement = null;
  let lastFilterTrigger = null;
  const filterState = {
    text: '',
    categories: new Set(),
    sources: new Set(),
    cves: false,
    actors: false,
    ttps: false,
    iocs: false,
  };
  const defaultEmptyMessage = emptyState ? emptyState.textContent : '';

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function normaliseList(value) {
    if (!value) {
      return [];
    }
    if (Array.isArray(value)) {
      return value.map((entry) => String(entry).trim()).filter(Boolean);
    }
    if (typeof value === 'string') {
      return value
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean);
    }
    return [String(value).trim()].filter(Boolean);
  }

  function sortFilterValues(values) {
    return values
      .filter(Boolean)
      .sort((a, b) => {
        if (a === 'General') {
          return -1;
        }
        if (b === 'General') {
          return 1;
        }
        return a.localeCompare(b, undefined, { sensitivity: 'base' });
      });
  }

  function summarise(text, maxLength) {
    if (!text) {
      return '';
    }
    const value = String(text).trim();
    if (value.length <= maxLength) {
      return value;
    }
    return `${value.slice(0, maxLength - 1).trim()}…`;
  }

  function parseDateValue(value) {
    if (!value) {
      return null;
    }
    if (value instanceof Date) {
      const timestamp = value.getTime();
      return Number.isNaN(timestamp) ? null : timestamp;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        return null;
      }
      if (value < 0) {
        return null;
      }
      return value < 1e12 ? value * 1000 : value;
    }
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed) {
        return null;
      }
      const parsed = Date.parse(trimmed);
      if (!Number.isNaN(parsed)) {
        return parsed;
      }
      const numeric = Number(trimmed);
      if (Number.isFinite(numeric)) {
        return parseDateValue(numeric);
      }
    }
    return null;
  }

  function resolveArticleTimestamp(article) {
    const candidates = [
      article.date,
      article.published,
      article.timestamp,
      article.published_at,
      article.created_at,
      article.updated_at,
    ];
    for (let i = 0; i < candidates.length; i += 1) {
      const timestamp = parseDateValue(candidates[i]);
      if (timestamp !== null) {
        return timestamp;
      }
    }
    return 0;
  }

  function renderPills(container, values) {
    container.textContent = '';
    values.forEach((value) => {
      const pill = document.createElement('span');
      pill.className = 'drawer__pill';
      pill.textContent = value;
      container.appendChild(pill);
    });
  }

  function renderList(container, values) {
    container.textContent = '';
    values.forEach((value) => {
      const item = document.createElement('li');
      item.textContent = value;
      container.appendChild(item);
    });
  }

  function showSection(key, hasContent) {
    const section = sectionNodes.get(key);
    if (!section) {
      return;
    }
    if (hasContent) {
      section.classList.add('is-visible');
    } else {
      section.classList.remove('is-visible');
    }
  }

  function hasActiveFilters() {
    return (
      Boolean(filterState.text.trim()) ||
      filterState.categories.size > 0 ||
      filterState.sources.size > 0 ||
      filterState.cves ||
      filterState.actors ||
      filterState.ttps ||
      filterState.iocs
    );
  }

  function getActiveFilterCount() {
    let count = 0;
    if (filterState.text.trim()) {
      count += 1;
    }
    if (filterState.categories.size > 0) {
      count += 1;
    }
    if (filterState.sources.size > 0) {
      count += 1;
    }
    if (filterState.cves) {
      count += 1;
    }
    if (filterState.actors) {
      count += 1;
    }
    if (filterState.ttps) {
      count += 1;
    }
    if (filterState.iocs) {
      count += 1;
    }
    return count;
  }

  function matchesFilter(article) {
    const term = filterState.text.trim().toLowerCase();

    if (term) {
      const parts = [
        article.title,
        article.headline,
        article.summary,
        article['AI-Summary'],
        article.notes,
        article.description,
        article.primary_category,
      ];

      const aggregateLists = [
        normaliseList(article.categories),
        normaliseList(article.sources),
        normaliseList(article.ThreatActors || article.threat_actors),
        normaliseList(article.TTPs || article.ttps),
        normaliseList(article.CVEs || article.cves),
        normaliseList(article.iocs || article.IOCs),
      ];

      aggregateLists.forEach((values) => {
        if (values.length) {
          parts.push(values.join(' '));
        }
      });

      const hasTextMatch = parts.some((value) => {
        if (!value) {
          return false;
        }
        return String(value).toLowerCase().includes(term);
      });

      if (!hasTextMatch) {
        return false;
      }
    }

    if (filterState.categories.size > 0) {
      const categories = new Set(normaliseList(article.categories));
      const primaryCategory = article.primary_category;
      if (primaryCategory) {
        categories.add(String(primaryCategory).trim());
      }
      if (categories.size === 0) {
        categories.add('General');
      }
      let matchesCategory = false;
      filterState.categories.forEach((value) => {
        if (categories.has(value)) {
          matchesCategory = true;
        }
      });
      if (!matchesCategory) {
        return false;
      }
    }

    if (filterState.sources.size > 0) {
      const sources = new Set(normaliseList(article.sources));
      const fallbackSource = article.source || article.provider || article.feed_source;
      if (fallbackSource) {
        sources.add(String(fallbackSource).trim());
      }
      let matchesSource = false;
      filterState.sources.forEach((value) => {
        if (sources.has(value)) {
          matchesSource = true;
        }
      });
      if (!matchesSource) {
        return false;
      }
    }

    if (filterState.cves) {
      if (normaliseList(article.CVEs || article.cves).length === 0) {
        return false;
      }
    }

    if (filterState.actors) {
      if (normaliseList(article.ThreatActors || article.threat_actors).length === 0) {
        return false;
      }
    }

    if (filterState.ttps) {
      if (normaliseList(article.TTPs || article.ttps).length === 0) {
        return false;
      }
    }

    if (filterState.iocs) {
      if (normaliseList(article.iocs || article.IOCs).length === 0) {
        return false;
      }
    }

    return true;
  }

  function updateFilterToggleLabel(visibleCount) {
    if (!filterToggle) {
      return;
    }
    const activeCount = getActiveFilterCount();
    if (filterToggleLabel) {
      if (activeCount > 0) {
        filterToggleLabel.textContent = `Filters (${activeCount})`;
      } else {
        filterToggleLabel.textContent = 'Advanced filters';
      }
    }
    if (activeCount > 0) {
      filterToggle.setAttribute(
        'aria-label',
        `Adjust filters. ${visibleCount} visible with ${activeCount} active filter${activeCount === 1 ? '' : 's'}.`,
      );
    } else {
      filterToggle.setAttribute('aria-label', 'Open advanced filters');
    }
  }

  function showDrawer(article) {
    activeArticle = article;
    document.body.classList.add('drawer-open');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    drawer.classList.add('is-visible');
    requestAnimationFrame(() => {
      drawerSurface.focus({ preventScroll: true });
    });
  }

  function hideDrawer() {
    if (!drawer.classList.contains('is-visible')) {
      return;
    }
    drawer.classList.remove('is-visible');
    drawer.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('drawer-open');
    window.setTimeout(() => {
      drawer.hidden = true;
      activeArticle = null;
      if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') {
        try {
          lastFocusedElement.focus({ preventScroll: true });
        } catch (error) {
          lastFocusedElement.focus();
        }
      }
      lastFocusedElement = null;
    }, 280);
  }

  function populateDrawer(article) {
    if (!article) {
      return;
    }

    const categories = normaliseList(article.categories);
    const primaryCategory = article.primary_category || categories[0] || 'General';
    const allCategories = categories.length ? categories : [primaryCategory];

    if (detailRefs.categories) {
      detailRefs.categories.innerHTML = allCategories
        .map((name) => `<span>${escapeHTML(name)}</span>`)
        .join('');
    }

    if (detailRefs.title) {
      const title = article.title || article.headline || 'Untitled intelligence item';
      detailRefs.title.textContent = title;
    }

    if (detailRefs.source) {
      const sourceList = normaliseList(article.sources);
      const fallback = article.source || sourceList[0] || 'Unknown source';
      detailRefs.source.textContent = fallback;
    }

    if (detailRefs.date) {
      const dateValue = article.date || article.published || article.timestamp;
      detailRefs.date.textContent = dateValue ? String(dateValue) : '';
    }

    if (detailRefs.link) {
      const url = article.url || article.link || article.article_url;
      if (url) {
        detailRefs.link.href = url;
        detailRefs.link.removeAttribute('hidden');
      } else {
        detailRefs.link.href = '#';
        detailRefs.link.setAttribute('hidden', 'hidden');
      }
    }

    if (detailRefs.summary) {
      const summary = article['AI-Summary'] || article.summary;
      detailRefs.summary.textContent = summary ? String(summary) : '';
      showSection('summary', Boolean(summary));
    }

    if (detailRefs.notes) {
      const notes = article.notes;
      detailRefs.notes.textContent = notes ? String(notes) : '';
      showSection('notes', Boolean(notes));
    }

    const actors = normaliseList(article.ThreatActors || article.threat_actors);
    if (detailRefs.ThreatActors) {
      renderPills(detailRefs.ThreatActors, actors);
      showSection('ThreatActors', actors.length > 0);
    }

    const ttps = normaliseList(article.TTPs || article.ttps);
    if (detailRefs.TTPs) {
      renderPills(detailRefs.TTPs, ttps);
      showSection('TTPs', ttps.length > 0);
    }

    const iocs = normaliseList(article.iocs || article.IOCs);
    if (detailRefs.iocs) {
      renderPills(detailRefs.iocs, iocs);
      showSection('iocs', iocs.length > 0);
    }

    const cves = normaliseList(article.CVEs || article.cves);
    if (detailRefs.CVEs) {
      renderList(detailRefs.CVEs, cves);
      showSection('CVEs', cves.length > 0);
    }
  }

  function handleCardSelect(event) {
    const target = event.currentTarget;
    if (!target) {
      return;
    }
    const index = Number(target.getAttribute('data-article-index'));
    if (Number.isNaN(index) || !articles[index]) {
      return;
    }
    lastFocusedElement = target;
    populateDrawer(articles[index]);
    showDrawer(articles[index]);
  }

  const columnOrder = [];
  const columns = new Map();
  const availableCategories = new Set();
  const availableSources = new Set();

  articles.forEach((article, index) => {
    const categories = normaliseList(article.categories);
    const primaryCategory = article.primary_category || categories[0] || 'General';
    const resolvedCategory = primaryCategory || 'General';
    if (!columns.has(resolvedCategory)) {
      columns.set(resolvedCategory, []);
      columnOrder.push(resolvedCategory);
    }
    const timestamp = resolveArticleTimestamp(article);
    columns.get(resolvedCategory).push({ article, index, timestamp });

    if (primaryCategory) {
      availableCategories.add(String(primaryCategory).trim());
    }
    if (categories.length === 0 && !article.primary_category) {
      availableCategories.add('General');
    }
    categories.forEach((category) => {
      if (category) {
        availableCategories.add(category);
      }
    });

    const sourceList = normaliseList(article.sources);
    const fallbackSource = article.source || article.provider || article.feed_source;
    if (fallbackSource) {
      sourceList.push(String(fallbackSource).trim());
    }
    sourceList.forEach((source) => {
      if (source) {
        availableSources.add(source);
      }
    });
  });

  columnOrder.forEach((categoryName) => {
    const items = columns.get(categoryName);
    if (items) {
      items.sort((a, b) => {
        if (b.timestamp !== a.timestamp) {
          return b.timestamp - a.timestamp;
        }
        return a.index - b.index;
      });
    }
  });

  const sortedCategoryOptions = sortFilterValues(Array.from(availableCategories));
  const sortedSourceOptions = sortFilterValues(Array.from(availableSources));

  function renderOptionList(container, values, stateSet) {
    if (!container) {
      return;
    }
    container.textContent = '';
    values.forEach((value) => {
      const option = document.createElement('label');
      option.className = 'filter-panel__option';
      option.setAttribute('data-filter-value', value);

      const input = document.createElement('input');
      input.type = 'checkbox';
      input.value = value;
      input.checked = stateSet.has(value);
      option.classList.toggle('is-active', input.checked);

      input.addEventListener('change', () => {
        if (input.checked) {
          stateSet.add(value);
        } else {
          stateSet.delete(value);
        }
        option.classList.toggle('is-active', input.checked);
        handleFiltersUpdated();
      });

      const caption = document.createElement('span');
      caption.textContent = value;

      option.appendChild(input);
      option.appendChild(caption);
      container.appendChild(option);
    });
  }

  renderOptionList(categoryListNode, sortedCategoryOptions, filterState.categories);
  renderOptionList(sourceListNode, sortedSourceOptions, filterState.sources);

  function renderBoard() {
    let visibleCount = 0;
    let hasMatches = false;
    const filtersActive = hasActiveFilters();

    board.textContent = '';

    columnOrder.forEach((categoryName) => {
      const items = columns.get(categoryName) || [];
      const matchingItems = items.filter(({ article }) => matchesFilter(article));

      if (matchingItems.length === 0) {
        return;
      }

      hasMatches = true;
      visibleCount += matchingItems.length;

      const column = document.createElement('section');
      column.className = 'column';

      const header = document.createElement('header');
      header.className = 'column__header';

      const title = document.createElement('h2');
      title.className = 'column__title';
      title.textContent = categoryName;
      header.appendChild(title);

      const count = document.createElement('span');
      count.className = 'column__count';
      count.textContent = `${matchingItems.length} item${matchingItems.length === 1 ? '' : 's'}`;
      header.appendChild(count);

      column.appendChild(header);

      const list = document.createElement('div');
      list.className = 'column__cards';

      matchingItems.forEach(({ article, index }) => {
        const card = document.createElement('article');
        card.className = 'card';
        card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'button');
        card.setAttribute('data-article-index', String(index));

        const cardHeader = document.createElement('div');
        cardHeader.className = 'card__header';
        const source = normaliseList(article.sources)[0] || article.source || 'Unknown source';
        const dateLabel = article.date || article.published || article.timestamp || '';
        cardHeader.innerHTML = `<span>${escapeHTML(source)}</span><span>${escapeHTML(dateLabel)}</span>`;

        const summary = document.createElement('p');
        summary.className = 'card__summary';
        const summaryText = article['AI-Summary'] || article.summary || article.title || '';
        summary.textContent = summarise(summaryText, 260);

        const footer = document.createElement('div');
        footer.className = 'card__footer';

        const linkTarget = article.url || article.link || article.article_url;
        if (linkTarget) {
          const linkButton = document.createElement('a');
          linkButton.className = 'card__link-button';
          linkButton.href = linkTarget;
          linkButton.target = '_blank';
          linkButton.rel = 'noopener noreferrer';
          linkButton.textContent = 'View article';
          linkButton.addEventListener('click', (event) => {
            event.stopPropagation();
          });
          footer.appendChild(linkButton);
        }

        const meta = document.createElement('div');
        meta.className = 'card__meta';
        const cves = normaliseList(article.CVEs || article.cves);
        const actors = normaliseList(article.ThreatActors || article.threat_actors);
        const ttps = normaliseList(article.TTPs || article.ttps);
        const iocs = normaliseList(article.iocs || article.IOCs);

        const metaEntries = [];
        if (cves.length) {
          metaEntries.push(`${cves.length} CVE${cves.length === 1 ? '' : 's'}`);
        }
        if (actors.length) {
          metaEntries.push(`${actors.length} actor${actors.length === 1 ? '' : 's'}`);
        }
        if (ttps.length) {
          metaEntries.push(`${ttps.length} TTP${ttps.length === 1 ? '' : 's'}`);
        }
        if (iocs.length) {
          metaEntries.push(`${iocs.length} IOC${iocs.length === 1 ? '' : 's'}`);
        }

        if (metaEntries.length === 0) {
          metaEntries.push('No enrichment available');
        }

        metaEntries.forEach((entry) => {
          const pill = document.createElement('span');
          pill.className = 'card__meta-pill';
          pill.textContent = entry;
          meta.appendChild(pill);
        });

        footer.appendChild(meta);

        card.appendChild(cardHeader);
        card.appendChild(summary);
        card.appendChild(footer);

        card.addEventListener('click', handleCardSelect);
        card.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            handleCardSelect(event);
          }
        });

        list.appendChild(card);
      });

      column.appendChild(list);
      board.appendChild(column);
    });

    if (!hasMatches) {
      if (emptyState) {
        emptyState.hidden = false;
        emptyState.textContent = filtersActive
          ? 'No articles match your filters.'
          : defaultEmptyMessage;
        board.appendChild(emptyState);
      }
    } else if (emptyState) {
      emptyState.hidden = true;
      emptyState.textContent = defaultEmptyMessage;
      if (emptyState.isConnected) {
        emptyState.remove();
      }
    }

    if (totalCountLabel) {
      if (filtersActive) {
        totalCountLabel.textContent = `Showing ${visibleCount} of ${articles.length} items`;
      } else {
        totalCountLabel.textContent = `${articles.length} item${articles.length === 1 ? '' : 's'}`;
      }
    }

    if (filterTextInput) {
      filterTextInput.setAttribute('aria-label', `Keyword filter, ${visibleCount} articles match`);
    }

    updateFilterToggleLabel(visibleCount);

    return { visibleCount };
  }

  function handleFiltersUpdated() {
    const { visibleCount } = renderBoard();
    if (activeArticle && !matchesFilter(activeArticle)) {
      hideDrawer();
    }
    return visibleCount;
  }

  function openFilterPanel() {
    if (!filterPanel || !filterSurface) {
      return;
    }
    if (filterPanel.classList.contains('is-visible')) {
      return;
    }
    lastFilterTrigger = document.activeElement;
    filterPanel.hidden = false;
    filterPanel.setAttribute('aria-hidden', 'false');
    filterPanel.classList.add('is-visible');
    document.body.classList.add('filter-open');
    if (filterToggle) {
      filterToggle.setAttribute('aria-expanded', 'true');
    }
    const focusTarget = filterTextInput || filterSurface;
    requestAnimationFrame(() => {
      if (focusTarget && typeof focusTarget.focus === 'function') {
        try {
          focusTarget.focus({ preventScroll: true });
        } catch (error) {
          focusTarget.focus();
        }
      }
    });
  }

  function closeFilterPanel() {
    if (!filterPanel || !filterPanel.classList.contains('is-visible')) {
      return;
    }
    filterPanel.classList.remove('is-visible');
    filterPanel.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('filter-open');
    if (filterToggle) {
      filterToggle.setAttribute('aria-expanded', 'false');
    }
    window.setTimeout(() => {
      if (filterPanel && !filterPanel.classList.contains('is-visible')) {
        filterPanel.hidden = true;
      }
      const focusTarget = lastFilterTrigger || filterToggle;
      if (focusTarget && typeof focusTarget.focus === 'function') {
        try {
          focusTarget.focus({ preventScroll: true });
        } catch (error) {
          focusTarget.focus();
        }
      }
      lastFilterTrigger = null;
    }, 260);
  }

  renderBoard();

  if (typeof Intl !== 'undefined' && lastSyncLabel) {
    try {
      const timestamp = new Date();
      const formatter = new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
      });
      lastSyncLabel.textContent = `Updated ${formatter.format(timestamp)}`;
    } catch (error) {
      lastSyncLabel.textContent = 'Updated just now';
    }
  }

  closeControls.forEach((control) => {
    control.addEventListener('click', hideDrawer);
  });

  drawer.addEventListener('click', (event) => {
    if (event.target === drawer) {
      hideDrawer();
    }
  });

  drawer.addEventListener('transitionend', (event) => {
    if (event.propertyName === 'transform' && !drawer.classList.contains('is-visible')) {
      drawer.hidden = true;
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (filterPanel && filterPanel.classList.contains('is-visible')) {
        closeFilterPanel();
        return;
      }
      hideDrawer();
    }
  });

  if (filterToggle && filterPanel && filterSurface) {
    filterToggle.addEventListener('click', () => {
      openFilterPanel();
    });
  }

  filterCloseControls.forEach((control) => {
    control.addEventListener('click', closeFilterPanel);
  });

  if (applyFiltersButton) {
    applyFiltersButton.addEventListener('click', () => {
      closeFilterPanel();
    });
  }

  if (filterPanel && filterSurface) {
    filterPanel.addEventListener('transitionend', (event) => {
      if (event.target === filterSurface && event.propertyName === 'transform' && !filterPanel.classList.contains('is-visible')) {
        filterPanel.hidden = true;
      }
    });
  }

  if (filterTextInput) {
    filterTextInput.value = filterState.text;
    filterTextInput.addEventListener('input', (event) => {
      filterState.text = event.target.value || '';
      handleFiltersUpdated();
    });
  }

  const flagKeyMap = {
    cves: 'cves',
    actors: 'actors',
    ttps: 'ttps',
    iocs: 'iocs',
  };

  enrichmentFlags.forEach((flagControl) => {
    const flagKey = flagControl.getAttribute('data-filter-flag');
    const stateKey = flagKey ? flagKeyMap[flagKey] : undefined;
    if (!stateKey) {
      return;
    }
    const wrapper = flagControl.closest('.filter-panel__chip');
    filterState[stateKey] = Boolean(flagControl.checked);
    if (wrapper) {
      wrapper.classList.toggle('is-active', flagControl.checked);
    }
    flagControl.addEventListener('change', () => {
      const isChecked = flagControl.checked;
      filterState[stateKey] = isChecked;
      if (wrapper) {
        wrapper.classList.toggle('is-active', isChecked);
      }
      handleFiltersUpdated();
    });
  });

  if (clearFiltersButton) {
    clearFiltersButton.addEventListener('click', () => {
      filterState.text = '';
      filterState.categories.clear();
      filterState.sources.clear();
      filterState.cves = false;
      filterState.actors = false;
      filterState.ttps = false;
      filterState.iocs = false;

      if (filterTextInput) {
        filterTextInput.value = '';
      }

      if (categoryListNode) {
        Array.from(categoryListNode.querySelectorAll('input')).forEach((input) => {
          input.checked = false;
          const option = input.closest('.filter-panel__option');
          if (option) {
            option.classList.remove('is-active');
          }
        });
      }

      if (sourceListNode) {
        Array.from(sourceListNode.querySelectorAll('input')).forEach((input) => {
          input.checked = false;
          const option = input.closest('.filter-panel__option');
          if (option) {
            option.classList.remove('is-active');
          }
        });
      }

      enrichmentFlags.forEach((flagControl) => {
        flagControl.checked = false;
        const wrapper = flagControl.closest('.filter-panel__chip');
        if (wrapper) {
          wrapper.classList.remove('is-active');
        }
      });

      handleFiltersUpdated();
    });
  }
})();
