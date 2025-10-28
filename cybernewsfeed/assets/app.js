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
    content: drawer.querySelector('[data-detail="content"]'),
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

  function formatRichText(text) {
    if (!text) {
      return '';
    }
    const safe = escapeHTML(text);
    const parts = safe.split(/\n{2,}/);
    if (parts.length === 1) {
      return `<p>${safe.replace(/\n/g, '<br>')}</p>`;
    }
    return parts
      .map((paragraph) => `<p>${paragraph.replace(/\n/g, '<br>')}</p>`)
      .join('');
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

    if (detailRefs.content) {
      const contentValue = article.content || article.contents || '';
      const markup = formatRichText(String(contentValue || '').trim());
      detailRefs.content.innerHTML = markup;
      showSection('content', Boolean(contentValue));
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

  articles.forEach((article, index) => {
    const categories = normaliseList(article.categories);
    const primaryCategory = article.primary_category || categories[0] || 'General';
    if (!columns.has(primaryCategory)) {
      columns.set(primaryCategory, []);
      columnOrder.push(primaryCategory);
    }
    columns.get(primaryCategory).push({ article, index });
  });

  if (columns.size === 0) {
    if (emptyState) {
      emptyState.hidden = false;
    }
  } else {
    if (emptyState) {
      emptyState.hidden = true;
    }
    board.textContent = '';

    columnOrder.forEach((categoryName) => {
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
      const items = columns.get(categoryName) || [];
      count.textContent = `${items.length} item${items.length === 1 ? '' : 's'}`;
      header.appendChild(count);

      column.appendChild(header);

      const list = document.createElement('div');
      list.className = 'column__cards';

      items.forEach(({ article, index }) => {
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
          footer.appendChild(pill);
        });

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
  }

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

  if (totalCountLabel) {
    totalCountLabel.textContent = `${articles.length} item${articles.length === 1 ? '' : 's'}`;
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
      hideDrawer();
    }
  });
})();
