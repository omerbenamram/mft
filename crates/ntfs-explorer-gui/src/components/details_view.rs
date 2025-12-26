use dioxus::prelude::*;
use ntfs::ntfs::filesystem::join_ntfs_child_path;

use crate::components::{ContextMenuState, ResizeOverlay};
use crate::icons;

#[linkme::distributed_slice(crate::styles::STYLESHEETS)]
static DETAILS_VIEW_CSS: crate::styles::Stylesheet = crate::styles::Stylesheet {
    order: 200,
    name: "components/details_view",
    href: asset!("/src/components/details_view.css"),
};

/// A file or folder entry in the details list.
#[derive(Clone, Debug, PartialEq)]
pub struct EntryRow {
    pub name: String,
    pub entry_id: u64,
    pub is_dir: bool,
    pub is_deleted: bool,
    pub efs_encrypted: bool,
    pub size_bytes: u64,
    pub modified_unix_s: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SortKey {
    Name,
    Modified,
    Type,
    Size,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResizeCol {
    Modified,
    Type,
    Size,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ColResizeState {
    col: ResizeCol,
    start_x: f64,
    start_px: i32,
}

#[component]
pub fn DetailsView(
    entries: Vec<EntryRow>,
    base_path: String,
    is_loading: bool,
    error: Option<String>,
    has_snapshot: bool,
    selected: Option<(u64, String)>,

    col_modified_px: i32,
    col_type_px: i32,
    col_size_px: i32,
    on_set_col_modified_px: Callback<i32>,
    on_set_col_type_px: Callback<i32>,
    on_set_col_size_px: Callback<i32>,
    on_persist_layout: Callback<()>,

    on_navigate_up: Callback<()>,
    on_clear_selection: Callback<()>,
    on_select_dir: Callback<(u64, String)>,
    on_select_entry: Callback<EntryRow>,
    on_show_context_menu: Callback<ContextMenuState>,
) -> Element {
    // Sorting state (local to the table).
    let sort_key: Signal<SortKey> = use_signal(|| SortKey::Name);
    let sort_dir: Signal<SortDir> = use_signal(|| SortDir::Asc);

    let col_resize: Signal<Option<ColResizeState>> = use_signal(|| None);

    let on_sort = {
        let mut sort_key = sort_key;
        let mut sort_dir = sort_dir;
        Callback::new(move |key: SortKey| {
            if *sort_key.read() == key {
                let next = match *sort_dir.read() {
                    SortDir::Asc => SortDir::Desc,
                    SortDir::Desc => SortDir::Asc,
                };
                sort_dir.set(next);
                return;
            }

            sort_key.set(key);
            let default_dir = match key {
                SortKey::Name => SortDir::Asc,
                SortKey::Type => SortDir::Asc,
                SortKey::Modified => SortDir::Desc,
                SortKey::Size => SortDir::Desc,
            };
            sort_dir.set(default_dir);
        })
    };

    let on_col_resize_start = {
        let mut col_resize = col_resize;
        Callback::new(move |(col, e): (ResizeCol, MouseEvent)| {
            e.prevent_default();
            e.stop_propagation();
            let x = e.client_coordinates().x;
            let start_px = match col {
                ResizeCol::Modified => col_modified_px,
                ResizeCol::Type => col_type_px,
                ResizeCol::Size => col_size_px,
            };
            col_resize.set(Some(ColResizeState {
                col,
                start_x: x,
                start_px,
            }));
        })
    };
    let on_col_resize_move = {
        let col_resize = col_resize.to_owned();
        Callback::new(move |e: MouseEvent| {
            let Some(state) = *col_resize.read() else {
                return;
            };
            let x = e.client_coordinates().x;
            let delta = x - state.start_x;
            let next = (state.start_px as f64 + delta).round() as i32;
            let next = next.clamp(90, 420);
            match state.col {
                ResizeCol::Modified => on_set_col_modified_px.call(next),
                ResizeCol::Type => on_set_col_type_px.call(next),
                ResizeCol::Size => on_set_col_size_px.call(next),
            }
        })
    };
    let on_col_resize_end = {
        let mut col_resize = col_resize;
        Callback::new(move |_e: MouseEvent| {
            col_resize.set(None);
            on_persist_layout.call(());
        })
    };

    let sort_key_now = *sort_key.read();
    let sort_dir_now = *sort_dir.read();

    let mut entries = entries;
    sort_entries_in_place(&mut entries, sort_key_now, sort_dir_now);

    let entries_for_keys = entries.clone();
    let selected_for_keys = selected.clone();
    let base_path_for_keys = base_path.clone();

    let table_style = format!(
        "--col-modified: {}px; --col-type: {}px; --col-size: {}px;",
        col_modified_px, col_type_px, col_size_px
    );

    rsx! {
        div {
            class: "details-view",
            id: "details-kbd-root",
            tabindex: "0",
            style: "{table_style}",
            onkeydown: move |e: KeyboardEvent| {
                // Ignore modified shortcuts (Cmd/Ctrl/etc); those are handled by menus.
                let mods = e.modifiers();
                if mods.contains(Modifiers::ALT)
                    || mods.contains(Modifiers::CONTROL)
                    || mods.contains(Modifiers::META)
                    || mods.contains(Modifiers::SUPER)
                {
                    return;
                }

                let len = entries_for_keys.len();
                if len == 0 {
                    if e.code() == Code::Escape {
                        e.prevent_default();
                        on_clear_selection.call(());
                    }
                    return;
                }

                let cur_idx = selected_for_keys.as_ref().and_then(|(id, name)| {
                    entries_for_keys
                        .iter()
                        .position(|r| r.entry_id == *id && r.name == *name)
                });

                let select_idx = |idx: usize| {
                    let idx = idx.min(len.saturating_sub(1));
                    on_select_entry.call(entries_for_keys[idx].clone());
                    // Keep selection visible.
                    let _ = document::eval(
                        "document.querySelector('.details-row.is-selected')?.scrollIntoView({block:'nearest'});",
                    );
                };

                match e.code() {
                    Code::ArrowDown => {
                        e.prevent_default();
                        let next = cur_idx.map(|i| (i + 1).min(len - 1)).unwrap_or(0);
                        select_idx(next);
                    }
                    Code::ArrowUp => {
                        e.prevent_default();
                        let next = cur_idx
                            .and_then(|i| i.checked_sub(1))
                            .unwrap_or(len.saturating_sub(1));
                        select_idx(next);
                    }
                    Code::Home => {
                        e.prevent_default();
                        select_idx(0);
                    }
                    Code::End => {
                        e.prevent_default();
                        select_idx(len.saturating_sub(1));
                    }
                    Code::PageDown => {
                        e.prevent_default();
                        let step = 12usize;
                        let next = cur_idx.map(|i| (i + step).min(len - 1)).unwrap_or(0);
                        select_idx(next);
                    }
                    Code::PageUp => {
                        e.prevent_default();
                        let step = 12usize;
                        let next = cur_idx.map(|i| i.saturating_sub(step)).unwrap_or(0);
                        select_idx(next);
                    }
                    Code::Enter | Code::NumpadEnter | Code::ArrowRight => {
                        // Enter/right: open selected folder.
                        if let Some(i) = cur_idx {
                            let r = &entries_for_keys[i];
                            if r.is_dir {
                                e.prevent_default();
                                let next_path = join_ntfs_child_path(
                                    base_path_for_keys.as_str(),
                                    r.name.as_str(),
                                );
                                on_select_dir.call((r.entry_id, next_path));
                            }
                        }
                    }
                    Code::Backspace | Code::ArrowLeft => {
                        e.prevent_default();
                        on_navigate_up.call(());
                    }
                    Code::Escape => {
                        e.prevent_default();
                        on_clear_selection.call(());
                    }
                    _ => {}
                }
            },
            // Column headers (sortable + resizable)
            div { class: "details-header",
                button {
                    r#type: "button",
                    class: format!("details-header-cell col-name {}", if sort_key_now == SortKey::Name { "is-sorted" } else { "" }),
                    onclick: move |_| on_sort.call(SortKey::Name),
                    span { class: "details-header-text", "Name" }
                    span { class: "details-sort-indicator",
                        {sort_indicator(sort_key_now == SortKey::Name, sort_dir_now)}
                    }
                }
                button {
                    r#type: "button",
                    class: format!("details-header-cell col-modified {}", if sort_key_now == SortKey::Modified { "is-sorted" } else { "" }),
                    onclick: move |_| on_sort.call(SortKey::Modified),
                    span { class: "details-header-text", "Date modified" }
                    span { class: "details-sort-indicator",
                        {sort_indicator(sort_key_now == SortKey::Modified, sort_dir_now)}
                    }
                    div {
                        class: "col-resizer",
                        onmousedown: move |e| on_col_resize_start.call((ResizeCol::Modified, e)),
                    }
                }
                button {
                    r#type: "button",
                    class: format!("details-header-cell col-type {}", if sort_key_now == SortKey::Type { "is-sorted" } else { "" }),
                    onclick: move |_| on_sort.call(SortKey::Type),
                    span { class: "details-header-text", "Type" }
                    span { class: "details-sort-indicator",
                        {sort_indicator(sort_key_now == SortKey::Type, sort_dir_now)}
                    }
                    div {
                        class: "col-resizer",
                        onmousedown: move |e| on_col_resize_start.call((ResizeCol::Type, e)),
                    }
                }
                button {
                    r#type: "button",
                    class: format!("details-header-cell col-size {}", if sort_key_now == SortKey::Size { "is-sorted" } else { "" }),
                    onclick: move |_| on_sort.call(SortKey::Size),
                    span { class: "details-header-text", "Size" }
                    span { class: "details-sort-indicator",
                        {sort_indicator(sort_key_now == SortKey::Size, sort_dir_now)}
                    }
                    div {
                        class: "col-resizer",
                        onmousedown: move |e| on_col_resize_start.call((ResizeCol::Size, e)),
                    }
                }
            }

            // Body
            div {
                class: "details-body",
                onclick: move |_| {
                    on_clear_selection.call(());
                    let _ = document::eval("document.getElementById('details-kbd-root')?.focus();");
                },
                if let Some(err) = error {
                    div { class: "error-banner", "{err}" }
                } else if is_loading {
                    div { class: "empty-state",
                        span { class: "details-spinner" }
                        span { class: "empty-state-title", "Loading…" }
                    }
                } else if !has_snapshot {
                    div { class: "empty-state",
                        span { class: "empty-state-icon", {icons::empty_folder_large()} }
                        span { class: "empty-state-title", "No snapshot loaded" }
                        span { class: "empty-state-subtitle",
                            "Open an NTFS image (full features) or an MFT snapshot (metadata-only)"
                        }
                    }
                } else if entries.is_empty() {
                    div { class: "empty-state",
                        span { class: "empty-state-icon", {icons::empty_folder_large()} }
                        span { class: "empty-state-title", "This folder is empty" }
                    }
                } else {
                    for entry in entries {
                        DetailsRow {
                            // Combine name + entry_id for unique key (handles deleted + live duplicates)
                            key: "{entry.name}-{entry.entry_id}",
                            entry: entry.clone(),
                            base_path: base_path.clone(),
                            selected: selected
                                .as_ref()
                                .is_some_and(|(id, name)| *id == entry.entry_id && name == &entry.name),
                            on_select_dir,
                            on_select_entry,
                            on_show_context_menu,
                        }
                    }
                }
            }

            if col_resize.read().is_some() {
                ResizeOverlay {
                    on_move: on_col_resize_move,
                    on_end: on_col_resize_end,
                }
            }
        }
    }
}

fn sort_indicator(active: bool, dir: SortDir) -> Element {
    if !active {
        return rsx! {};
    }
    rsx! {
        svg {
            width: "10",
            height: "10",
            view_box: "0 0 10 10",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            if dir == SortDir::Asc {
                path {
                    d: "M5 2L8 6H2L5 2Z",
                    fill: "currentColor",
                }
            } else {
                path {
                    d: "M5 8L2 4H8L5 8Z",
                    fill: "currentColor",
                }
            }
        }
    }
}

#[component]
fn DetailsRow(
    entry: EntryRow,
    base_path: String,
    selected: bool,
    on_select_dir: Callback<(u64, String)>,
    on_select_entry: Callback<EntryRow>,
    on_show_context_menu: Callback<ContextMenuState>,
) -> Element {
    let mut row_class = String::from("details-row");
    if selected {
        row_class.push_str(" is-selected");
    }
    if entry.is_deleted {
        row_class.push_str(" is-deleted");
    }
    if entry.efs_encrypted {
        row_class.push_str(" is-encrypted");
    }

    let type_label = if entry.is_dir { "File folder" } else { "File" };

    let size_str = if entry.is_dir {
        String::new()
    } else {
        format_size(entry.size_bytes)
    };

    let modified_str = format_timestamp(entry.modified_unix_s);

    // Closures need owned copies
    let entry_for_click = entry.clone();
    let entry_for_dblclick = entry.clone();
    let entry_for_context = entry.clone();
    let base_for_dblclick = base_path.clone();

    rsx! {
        div {
            class: "{row_class}",
            onclick: move |e: MouseEvent| {
                e.stop_propagation();
                on_select_entry.call(entry_for_click.clone());
                let _ = document::eval("document.getElementById('details-kbd-root')?.focus();");
            },
            ondoubleclick: move |_| {
                if entry_for_dblclick.is_dir {
                    let next_path = join_ntfs_child_path(
                        base_for_dblclick.as_str(),
                        entry_for_dblclick.name.as_str(),
                    );
                    on_select_dir.call((entry_for_dblclick.entry_id, next_path));
                }
            },
            oncontextmenu: move |e: MouseEvent| {
                e.stop_propagation();
                e.prevent_default();
                on_select_entry.call(entry_for_context.clone());
                let _ = document::eval("document.getElementById('details-kbd-root')?.focus();");
                let xy = e.client_coordinates();
                on_show_context_menu.call(ContextMenuState {
                    x: xy.x,
                    y: xy.y,
                    row: entry_for_context.clone(),
                });
            },

            // Name column
            div { class: "details-col col-name",
                span { class: "details-icon",
                    {entry_icon(&entry)}
                }
                span { class: "details-name", "{entry.name}" }
                if entry.is_deleted {
                    span { class: "details-badge is-deleted", "Deleted" }
                }
                if entry.efs_encrypted {
                    span { class: "details-badge is-encrypted", "Encrypted" }
                }
            }

            // Modified column
            div { class: "details-col col-modified", "{modified_str}" }

            // Type column
            div { class: "details-col col-type", "{type_label}" }

            // Size column
            div { class: "details-col col-size", "{size_str}" }
        }
    }
}

fn entry_icon(entry: &EntryRow) -> Element {
    if entry.is_dir {
        if entry.is_deleted {
            icons::folder_deleted()
        } else {
            icons::folder_closed()
        }
    } else if entry.is_deleted {
        icons::file_deleted()
    } else {
        icons::file_generic()
    }
}

fn format_size(bytes: u64) -> String {
    use bytesize::ByteSize;
    ByteSize(bytes).to_string()
}

fn format_timestamp(unix_s: i64) -> String {
    use jiff::Timestamp;
    use jiff::tz::TimeZone;

    let ts = match Timestamp::from_second(unix_s) {
        Ok(ts) => ts,
        Err(_) => return "—".to_string(),
    };
    ts.to_zoned(TimeZone::system())
        .strftime("%Y-%m-%d %H:%M")
        .to_string()
}

fn sort_entries_in_place(entries: &mut [EntryRow], key: SortKey, dir: SortDir) {
    use std::cmp::Ordering;

    let cmp_name = |a: &EntryRow, b: &EntryRow| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    };

    let key_cmp = |a: &EntryRow, b: &EntryRow| -> Ordering {
        match key {
            SortKey::Name => cmp_name(a, b),
            SortKey::Modified => a.modified_unix_s.cmp(&b.modified_unix_s),
            SortKey::Size => a.size_bytes.cmp(&b.size_bytes),
            SortKey::Type => file_type_key(a).cmp(&file_type_key(b)),
        }
    };

    entries.sort_by(|a, b| {
        // Explorer-style: folders first.
        match (a.is_dir, b.is_dir) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }

        let mut ord = key_cmp(a, b);
        if ord == Ordering::Equal {
            ord = cmp_name(a, b);
        }
        if ord == Ordering::Equal {
            ord = a.entry_id.cmp(&b.entry_id);
        }

        match dir {
            SortDir::Asc => ord,
            SortDir::Desc => ord.reverse(),
        }
    });
}

fn file_type_key(e: &EntryRow) -> String {
    if e.is_dir {
        return "folder".to_string();
    }
    match e.name.rsplit_once('.') {
        Some((_base, ext)) if !ext.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}
