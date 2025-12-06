# Table UI Guide

## Overview

All tables in NoClickOps now support enhanced filtering and sorting with keyboard navigation and regex search capabilities.

## Features

### 1. Sortable Columns

- Click the **↕** icon next to any column header to sort
- First click: descending order
- Second click: ascending order
- Third click: back to default/server order

### 2. Column Filtering

- Click the **⌃** icon (filter icon) on the right edge of column headers to open filter dropdown
- Each column maintains its own independent filter

### 3. Search with Regex Support

When a filter dropdown is open:

- Type in the search box to filter options
- **Regex support**: The search automatically tries to parse your input as a regex pattern
  - Example: `^api-` matches items starting with "api-"
  - Example: `prod|staging` matches items containing "prod" OR "staging"
  - Example: `\d{2,}` matches items with 2 or more digits
- If regex parsing fails, falls back to simple substring matching

### 4. Keyboard Navigation

#### Arrow Keys
- **↓ (Down Arrow)**: Move highlight down to next visible option
- **↑ (Up Arrow)**: Move highlight up to previous visible option
- The highlighted option has a blue background

#### Selection
- **Enter**: Toggle selection of the currently highlighted option
- Selected options show a checkmark (✓)

#### Apply Filters
- **Cmd+Space** (Mac) or **Ctrl+Space** (Windows/Linux): Close dropdown and apply selected filters
- This immediately filters the table based on your selections

#### Close Dropdown
- **Escape**: Close the filter dropdown without making changes

### 5. Multi-Select Filtering

- Click any option to toggle its selection
- Multiple options can be selected per column
- When multiple values are selected, rows matching ANY of the selected values are shown (OR logic)
- Filters across different columns use AND logic (all must match)

### 6. Column Visibility (Network page)

On the Network page, you can customize which columns are visible:

- Click the "Columns" dropdown
- Select/deselect columns to show/hide them
- Selections are saved to browser localStorage

## Keyboard Shortcuts Summary

| Key | Action |
|-----|--------|
| ↓ | Navigate down in dropdown |
| ↑ | Navigate up in dropdown |
| Enter | Toggle selection of highlighted option |
| Escape | Close dropdown |
| Cmd/Ctrl + Space | Apply filters and close dropdown |

## Supported Pages

The enhanced table functionality is available on:

- **Network** (`/network`) - Full filtering, sorting, column visibility
- **Network Trusts** (`/network-trusts`) - Filtering and sorting
- **Findings** (`/findings`) - Uses StandardTable with sorting and filtering
- **Port Scans** (`/portscans`) - Uses StandardTable with sorting and filtering

## Technical Details

### For Developers

The functionality is provided by:

1. **`/static/table-utils.js`**: StandardTable class for structured table management
2. **Inline implementations**: network.html and network_trusts.html have custom implementations
3. **Shared CSS**: `/static/style.css` contains common filter dropdown styles

To add to a new page:
```html
<!-- Include the table utilities -->
<script src="/static/table-utils.js"></script>

<!-- Initialize the table -->
<script>
  const table = new StandardTable('your-table-id', {
    defaultSort: 'column_key',
    defaultDir: -1  // -1 = desc, 1 = asc
  });
  
  table.setData(yourDataArray);
</script>
```

### CSS Classes

- `.filter-dropdown`: The dropdown container
- `.filter-search`: The search input field
- `.filter-options`: Container for filter options
- `.filter-option`: Individual filter option
- `.filter-option.selected`: Selected filter option
- `.filter-option.highlighted`: Keyboard-highlighted option
- `.filter-check`: Checkmark indicator

## Browser Compatibility

- Tested on modern versions of Chrome, Firefox, Safari, and Edge
- Requires ES6 support
- Uses CSS Grid and Flexbox
