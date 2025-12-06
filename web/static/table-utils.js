/**
 * Standardized table utilities for NoClickOps
 * Provides sortable columns and per-column filtering
 */

class StandardTable {
  constructor(tableId, options = {}) {
    this.tableId = tableId;
    this.table = document.getElementById(tableId);
    if (!this.table) throw new Error(`Table ${tableId} not found`);
    
    this.tbody = this.table.querySelector('tbody');
    this.thead = this.table.querySelector('thead');
    
    this.data = [];
    this.filteredData = [];
    this.sortKey = options.defaultSort || null;
    this.sortDir = options.defaultDir || -1; // -1 = desc, 1 = asc
    
    this.columns = this.extractColumns();
    this.filterState = this.initFilterState();
    
    this.setupHeaders();
    this.setupGlobalClickHandler();
  }
  
  extractColumns() {
    const ths = this.thead.querySelectorAll('th');
    const columns = [];
    
    ths.forEach((th, idx) => {
      const sortKey = th.getAttribute('data-sort');
      const filterKey = th.getAttribute('data-filter');
      const label = th.textContent.trim();
      
      columns.push({
        index: idx,
        label,
        sortKey,
        filterKey,
        th,
      });
    });
    
    return columns;
  }
  
  initFilterState() {
    const state = {};
    this.columns.forEach(col => {
      if (col.filterKey) {
        state[col.filterKey] = {
          options: [],
          selected: new Set(),
        };
      }
    });
    return state;
  }
  
  setupHeaders() {
    this.columns.forEach(col => {
      const wrapper = document.createElement('div');
      wrapper.className = 'th-wrap';
      
      const label = document.createElement('span');
      label.textContent = col.label;
      wrapper.appendChild(label);
      
      const actions = document.createElement('div');
      actions.className = 'th-actions';
      
      if (col.sortKey) {
        const sortIcon = document.createElement('span');
        sortIcon.className = 'sort-icon';
        sortIcon.textContent = '↕';
        sortIcon.dataset.sortKey = col.sortKey;
        actions.appendChild(sortIcon);
      }
      
      if (col.filterKey) {
        const filterIcon = document.createElement('span');
        filterIcon.className = 'filter-icon';
        filterIcon.textContent = '⌃';
        filterIcon.dataset.filterKey = col.filterKey;
        actions.appendChild(filterIcon);
        
        // Create filter dropdown
        this.createFilterDropdown(col);
      }
      
      wrapper.appendChild(actions);
      col.th.innerHTML = '';
      col.th.appendChild(wrapper);
    });
  }
  
  createFilterDropdown(col) {
    const dropdown = document.createElement('div');
    dropdown.className = 'filter-dropdown';
    dropdown.id = `filter-dd-${col.filterKey}`;
    dropdown.style.display = 'none';
    dropdown.dataset.filterKey = col.filterKey;
    
    const searchInput = document.createElement('input');
    searchInput.className = 'filter-search';
    searchInput.id = `filter-search-${col.filterKey}`;
    searchInput.placeholder = 'Search (supports regex)...';
    searchInput.style.width = '100%';
    searchInput.style.padding = '8px';
    searchInput.style.marginBottom = '8px';
    searchInput.style.border = '1px solid var(--border)';
    searchInput.style.borderRadius = '4px';
    searchInput.style.background = 'rgba(255,255,255,0.05)';
    searchInput.style.color = 'var(--text-main)';
    
    const optionsContainer = document.createElement('div');
    optionsContainer.className = 'filter-options';
    optionsContainer.id = `filter-options-${col.filterKey}`;
    optionsContainer.style.maxHeight = '200px';
    optionsContainer.style.overflowY = 'auto';
    optionsContainer.style.display = 'flex';
    optionsContainer.style.flexDirection = 'column';
    optionsContainer.style.gap = '4px';
    
    dropdown.appendChild(searchInput);
    dropdown.appendChild(optionsContainer);
    col.th.appendChild(dropdown);
    
    // Stop propagation on dropdown click
    dropdown.addEventListener('click', (e) => e.stopPropagation());
    
    // Search handler with regex support
    searchInput.addEventListener('input', () => {
      this.filterFilterOptions(col.filterKey);
    });
    
    // Keyboard navigation for search input
    searchInput.addEventListener('keydown', (e) => {
      this.handleSearchKeydown(e, col.filterKey);
    });
  }
  
  setupGlobalClickHandler() {
    document.addEventListener('click', (e) => {
      const sortIcon = e.target.closest('.sort-icon');
      const filterIcon = e.target.closest('.filter-icon');
      
      if (sortIcon) {
        e.stopPropagation();
        const key = sortIcon.dataset.sortKey;
        this.handleSort(key);
      } else if (filterIcon) {
        e.stopPropagation();
        const key = filterIcon.dataset.filterKey;
        this.toggleFilterDropdown(key);
      } else if (!e.target.closest('.filter-dropdown')) {
        this.closeAllFilterDropdowns();
      }
    });
  }
  
  handleSort(key) {
    if (this.sortKey === key) {
      this.sortDir = -this.sortDir;
    } else {
      this.sortKey = key;
      this.sortDir = -1;
    }
    this.render();
  }
  
  toggleFilterDropdown(key) {
    const dropdown = document.getElementById(`filter-dd-${key}`);
    if (!dropdown) return;
    
    const isVisible = dropdown.style.display === 'block';
    this.closeAllFilterDropdowns();
    
    if (!isVisible) {
      dropdown.style.display = 'block';
      const searchInput = document.getElementById(`filter-search-${key}`);
      if (searchInput) {
        searchInput.value = '';
        this.filterFilterOptions(key);
        setTimeout(() => searchInput.focus(), 10);
      }
    }
  }
  
  closeAllFilterDropdowns() {
    document.querySelectorAll('.filter-dropdown').forEach(dd => {
      dd.style.display = 'none';
    });
  }
  
  handleSearchKeydown(e, filterKey) {
    const optionsContainer = document.getElementById(`filter-options-${filterKey}`);
    if (!optionsContainer) return;
    
    const visibleOptions = Array.from(optionsContainer.querySelectorAll('.filter-option'))
      .filter(opt => opt.style.display !== 'none');
    
    if (visibleOptions.length === 0) return;
    
    // Handle Cmd+Space or Ctrl+Space to apply selected filters
    if ((e.metaKey || e.ctrlKey) && e.code === 'Space') {
      e.preventDefault();
      this.closeAllFilterDropdowns();
      this.render();
      return;
    }
    
    let currentIndex = parseInt(optionsContainer.dataset.highlightedIndex || '-1');
    
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        currentIndex = (currentIndex + 1) % visibleOptions.length;
        this.highlightOption(visibleOptions, currentIndex, optionsContainer);
        break;
        
      case 'ArrowUp':
        e.preventDefault();
        currentIndex = currentIndex <= 0 ? visibleOptions.length - 1 : currentIndex - 1;
        this.highlightOption(visibleOptions, currentIndex, optionsContainer);
        break;
        
      case 'Enter':
        e.preventDefault();
        if (currentIndex >= 0 && currentIndex < visibleOptions.length) {
          visibleOptions[currentIndex].click();
        }
        break;
        
      case 'Escape':
        e.preventDefault();
        this.closeAllFilterDropdowns();
        break;
    }
  }
  
  highlightOption(visibleOptions, index, container) {
    // Remove previous highlight
    this.removeHighlight(container);
    
    if (index >= 0 && index < visibleOptions.length) {
      const option = visibleOptions[index];
      option.classList.add('highlighted');
      option.style.background = 'rgba(100,149,237,0.3)'; // Cornflower blue highlight
      
      // Scroll into view if needed
      option.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      
      container.dataset.highlightedIndex = index;
    }
  }
  
  removeHighlight(container) {
    container.querySelectorAll('.filter-option.highlighted').forEach(opt => {
      opt.classList.remove('highlighted');
      const state = this.filterState[container.closest('.filter-dropdown')?.dataset.filterKey];
      if (state) {
        const optionText = opt.querySelector('span')?.textContent || opt.textContent.replace('✓', '').trim();
        opt.style.background = state.selected.has(optionText) ? 'rgba(255,255,255,0.08)' : '';
      }
    });
  }
  
  filterFilterOptions(key) {
    const searchInput = document.getElementById(`filter-search-${key}`);
    const optionsContainer = document.getElementById(`filter-options-${key}`);
    if (!searchInput || !optionsContainer) return;
    
    const term = searchInput.value;
    let regex = null;
    let useRegex = false;
    
    // Try to parse as regex
    if (term.length > 0) {
      try {
        regex = new RegExp(term, 'i');
        useRegex = true;
      } catch (e) {
        // If regex parsing fails, fall back to simple string matching
        useRegex = false;
      }
    }
    
    const options = optionsContainer.querySelectorAll('.filter-option');
    options.forEach((opt, index) => {
      const text = opt.querySelector('span')?.textContent || opt.textContent;
      let matches = false;
      
      if (!term) {
        matches = true;
      } else if (useRegex && regex) {
        matches = regex.test(text);
      } else {
        matches = text.toLowerCase().includes(term.toLowerCase());
      }
      
      opt.style.display = matches ? 'flex' : 'none';
      opt.dataset.optionIndex = index;
    });
    
    // Reset highlighted index when filter changes
    delete optionsContainer.dataset.highlightedIndex;
    this.removeHighlight(optionsContainer);
  }
  
  updateFilterOptions(key) {
    const state = this.filterState[key];
    if (!state) return;
    
    const container = document.getElementById(`filter-options-${key}`);
    if (!container) return;
    
    container.innerHTML = '';
    
    state.options.forEach(option => {
      const div = document.createElement('div');
      div.className = 'filter-option';
      if (state.selected.has(option)) {
        div.classList.add('selected');
      }
      
      div.style.display = 'flex';
      div.style.alignItems = 'center';
      div.style.justifyContent = 'space-between';
      div.style.padding = '6px 10px';
      div.style.borderRadius = '4px';
      div.style.cursor = 'pointer';
      
      const span = document.createElement('span');
      span.textContent = option;
      span.style.whiteSpace = 'normal';
      span.style.wordBreak = 'break-word';
      
      const check = document.createElement('span');
      check.className = 'filter-check';
      check.textContent = '✓';
      check.style.width = '16px';
      check.style.textAlign = 'right';
      check.style.visibility = state.selected.has(option) ? 'visible' : 'hidden';
      
      div.appendChild(span);
      div.appendChild(check);
      
      div.addEventListener('click', () => {
        if (state.selected.has(option)) {
          state.selected.delete(option);
        } else {
          state.selected.add(option);
        }
        this.updateFilterOptions(key);
        this.render();
      });
      
      div.addEventListener('mouseenter', () => {
        div.style.background = 'rgba(255,255,255,0.05)';
      });
      
      div.addEventListener('mouseleave', () => {
        div.style.background = state.selected.has(option) ? 'rgba(255,255,255,0.08)' : '';
      });
      
      container.appendChild(div);
    });
  }
  
  extractFilterOptions() {
    const filters = {};
    
    this.columns.forEach(col => {
      if (!col.filterKey) return;
      
      const values = new Set();
      this.data.forEach(row => {
        const val = this.getColumnValue(row, col.filterKey);
        if (val !== null && val !== undefined && val !== '') {
          values.add(String(val));
        }
      });
      
      filters[col.filterKey] = Array.from(values).sort();
    });
    
    return filters;
  }
  
  getColumnValue(row, key) {
    // Allow custom accessor function
    if (typeof row[key] === 'function') {
      return row[key]();
    }
    return row[key];
  }
  
  applyFilters() {
    this.filteredData = this.data.filter(row => {
      for (const key in this.filterState) {
        const state = this.filterState[key];
        if (state.selected.size === 0) continue;
        
        const value = String(this.getColumnValue(row, key) || '');
        if (!state.selected.has(value)) {
          return false;
        }
      }
      return true;
    });
  }
  
  applySort() {
    if (!this.sortKey) return;
    
    this.filteredData.sort((a, b) => {
      const av = this.getColumnValue(a, this.sortKey);
      const bv = this.getColumnValue(b, this.sortKey);
      
      let cmp = 0;
      if (typeof av === 'number' && typeof bv === 'number') {
        cmp = av === bv ? 0 : (av < bv ? -1 : 1);
      } else {
        const as = String(av || '').toLowerCase();
        const bs = String(bv || '').toLowerCase();
        cmp = as === bs ? 0 : (as < bs ? -1 : 1);
      }
      
      return cmp * this.sortDir;
    });
  }
  
  setData(data) {
    this.data = data;
    
    // Extract filter options
    const filters = this.extractFilterOptions();
    for (const key in filters) {
      if (this.filterState[key]) {
        this.filterState[key].options = filters[key];
        this.updateFilterOptions(key);
      }
    }
    
    this.render();
  }
  
  render() {
    this.applyFilters();
    this.applySort();
    
    if (this.filteredData.length === 0) {
      const colSpan = this.columns.length;
      this.tbody.innerHTML = `
        <tr>
          <td colspan="${colSpan}" style="text-align:center;padding:32px;color:var(--text-muted);">
            No data available
          </td>
        </tr>
      `;
      return;
    }
    
    this.tbody.innerHTML = this.filteredData.map(row => {
      const cells = this.columns.map(col => {
        const value = col.sortKey ? this.getColumnValue(row, col.sortKey) : 
                     col.filterKey ? this.getColumnValue(row, col.filterKey) : '';
        
        // Allow custom cell rendering
        if (row[`_render_${col.sortKey || col.filterKey}`]) {
          return `<td>${row[`_render_${col.sortKey || col.filterKey}`]}</td>`;
        }
        
        return `<td>${value !== null && value !== undefined ? value : '-'}</td>`;
      });
      
      return `<tr>${cells.join('')}</tr>`;
    }).join('');
  }
}

// Make available globally
window.StandardTable = StandardTable;
