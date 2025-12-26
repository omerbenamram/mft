use std::path::PathBuf;
use std::sync::Arc;

use dioxus::prelude::*;
use ntfs::ntfs::filesystem::{is_dot_dir_entry, join_ntfs_child_path};

use crate::components::{
    AddressBar, ContextMenu, ContextMenuState, DetailsView, EntryRow, NavigationPane, ResizeHandle,
    ResizeOverlay, StatusBar, Toolbar, TreeNode,
};
#[cfg(feature = "desktop")]
use crate::menus;
use crate::mft_only;
use crate::settings;
use crate::styles;

#[derive(Clone)]
struct LoadedSnapshot {
    path: PathBuf,
    backend: SnapshotBackend,
}

#[derive(Clone)]
enum SnapshotBackend {
    Ntfs(ntfs::ntfs::FileSystem),
    MftOnly(Arc<mft_only::MftOnlySnapshot>),
}

impl SnapshotBackend {
    fn is_mft_only(&self) -> bool {
        matches!(self, Self::MftOnly(_))
    }

    fn can_export(&self) -> bool {
        matches!(self, Self::Ntfs(_))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct NavResizeState {
    start_x: f64,
    start_width_px: i32,
}

pub fn app() -> Element {
    // Theme (light by default, like Windows 11)
    let theme = use_signal(|| "theme-light");

    // Persisted UI state (layout widths etc).
    let ui_state: Signal<settings::UiState> = use_signal(settings::load_ui_state);

    // Layout (resizing state only; widths are stored in `ui_state`)
    let nav_resize: Signal<Option<NavResizeState>> = use_signal(|| None);

    // Snapshot state
    let snapshot: Signal<Option<LoadedSnapshot>> = use_signal(|| None);
    let snapshot_error: Signal<Option<String>> = use_signal(|| None);
    let snapshot_loading = use_signal(|| false);
    let action_error: Signal<Option<String>> = use_signal(|| None);

    // Tree state
    let tree_root: Signal<Option<TreeNode>> = use_signal(|| None);
    let selected_dir_id: Signal<Option<u64>> = use_signal(|| None);

    // Directory view state
    let current_path = use_signal(|| "\\".to_string());
    let dir_entries: Signal<Vec<EntryRow>> = use_signal(Vec::new);
    let dir_loading = use_signal(|| false);
    let dir_error: Signal<Option<String>> = use_signal(|| None);
    let context_menu: Signal<Option<ContextMenuState>> = use_signal(|| None);
    let selected_entry: Signal<Option<(u64, String)>> = use_signal(|| None);

    // Native menubar events (Desktop).
    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::use_muda_event_handler;

        let mut snapshot = snapshot;
        let mut snapshot_error = snapshot_error;
        let mut snapshot_loading = snapshot_loading;
        let mut action_error = action_error;
        let mut tree_root = tree_root;
        let mut selected_dir_id = selected_dir_id;
        let mut current_path = current_path;
        let mut dir_entries = dir_entries;
        let mut dir_loading = dir_loading;
        let mut dir_error = dir_error;
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;

        use_muda_event_handler(move |event| {
            let id = event.id.as_ref();
            tracing::debug!(target = "ntfs_explorer.menu", id, "menu event");

            if id == menus::MENU_CLOSE_SNAPSHOT {
                snapshot.set(None);
                snapshot_error.set(None);
                snapshot_loading.set(false);
                action_error.set(None);
                tree_root.set(None);
                selected_dir_id.set(None);
                current_path.set("\\".to_string());
                dir_entries.set(Vec::new());
                dir_loading.set(false);
                dir_error.set(None);
                context_menu.set(None);
                selected_entry.set(None);
                return;
            }

            if id == menus::MENU_REFRESH {
                let Some(s) = snapshot.read().clone() else {
                    return;
                };
                let Some(dir_id) = *selected_dir_id.read() else {
                    return;
                };

                context_menu.set(None);
                action_error.set(None);

                let backend = s.backend.clone();
                dir_loading.set(true);
                dir_error.set(None);
                spawn(async move {
                    let res =
                        tokio::task::spawn_blocking(move || load_dir_listing(backend, dir_id))
                            .await;
                    match res {
                        Ok(Ok(v)) => dir_entries.set(v),
                        Ok(Err(e)) => dir_error.set(Some(e)),
                        Err(e) => dir_error.set(Some(format!("list task failed: {e}"))),
                    }
                    dir_loading.set(false);
                });
                return;
            }

            if id == menus::MENU_OPEN_SNAPSHOT {
                spawn(async move {
                    let Some(handle) = rfd::AsyncFileDialog::new()
                        .add_filter("Disk images", &["img", "dd", "raw", "e01", "aff"])
                        .pick_file()
                        .await
                    else {
                        return;
                    };
                    let path = handle.path().to_path_buf();

                    snapshot_loading.set(true);
                    snapshot_error.set(None);
                    action_error.set(None);
                    snapshot.set(None);
                    tree_root.set(None);
                    selected_dir_id.set(None);
                    current_path.set("\\".to_string());
                    dir_entries.set(Vec::new());
                    dir_loading.set(false);
                    dir_error.set(None);
                    context_menu.set(None);
                    selected_entry.set(None);

                    let opened = tokio::task::spawn_blocking(move || open_ntfs_image(path)).await;
                    match opened {
                        Ok(Ok(s)) => snapshot.set(Some(s)),
                        Ok(Err(e)) => snapshot_error.set(Some(e)),
                        Err(e) => snapshot_error.set(Some(format!("open task failed: {e}"))),
                    }

                    snapshot_loading.set(false);
                });
            }

            if id == menus::MENU_OPEN_MFT_SNAPSHOT {
                spawn(async move {
                    // Intentionally no extension filter: `$MFT` snapshots are often saved without
                    // an extension (e.g. `MFT`).
                    let Some(handle) = rfd::AsyncFileDialog::new().pick_file().await else {
                        return;
                    };
                    let path = handle.path().to_path_buf();

                    snapshot_loading.set(true);
                    snapshot_error.set(None);
                    action_error.set(None);
                    snapshot.set(None);
                    tree_root.set(None);
                    selected_dir_id.set(None);
                    current_path.set("\\".to_string());
                    dir_entries.set(Vec::new());
                    dir_loading.set(false);
                    dir_error.set(None);
                    context_menu.set(None);
                    selected_entry.set(None);

                    let opened = tokio::task::spawn_blocking(move || open_mft_snapshot(path)).await;
                    match opened {
                        Ok(Ok(s)) => snapshot.set(Some(s)),
                        Ok(Err(e)) => snapshot_error.set(Some(e)),
                        Err(e) => snapshot_error.set(Some(format!("open task failed: {e}"))),
                    }

                    snapshot_loading.set(false);
                });
            }
        });
    }

    // LiveView runs without a native menubar, so provide a path-based "open" flow.
    let mut open_path: Signal<String> = use_signal(String::new);

    let on_close_snapshot = {
        let mut snapshot = snapshot;
        let mut snapshot_error = snapshot_error;
        let mut snapshot_loading = snapshot_loading;
        let mut action_error = action_error;
        let mut tree_root = tree_root;
        let mut selected_dir_id = selected_dir_id;
        let mut current_path = current_path;
        let mut dir_entries = dir_entries;
        let mut dir_loading = dir_loading;
        let mut dir_error = dir_error;
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;

        Callback::new(move |(): ()| {
            snapshot.set(None);
            snapshot_error.set(None);
            snapshot_loading.set(false);
            action_error.set(None);
            tree_root.set(None);
            selected_dir_id.set(None);
            current_path.set("\\".to_string());
            dir_entries.set(Vec::new());
            dir_loading.set(false);
            dir_error.set(None);
            context_menu.set(None);
            selected_entry.set(None);
        })
    };

    let on_open_image_path = {
        let open_path = open_path.to_owned();
        let mut snapshot = snapshot;
        let mut snapshot_error = snapshot_error;
        let mut snapshot_loading = snapshot_loading;
        let mut action_error = action_error;
        let mut tree_root = tree_root;
        let mut selected_dir_id = selected_dir_id;
        let mut current_path = current_path;
        let mut dir_entries = dir_entries;
        let mut dir_loading = dir_loading;
        let mut dir_error = dir_error;
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;

        Callback::new(move |(): ()| {
            let raw = open_path.read().trim().to_string();
            if raw.is_empty() {
                snapshot_error.set(Some(
                    "Enter a path to an NTFS image (e.g. .img/.dd/.raw/.E01/.aff).".to_string(),
                ));
                return;
            }
            let path = PathBuf::from(raw);

            snapshot_loading.set(true);
            snapshot_error.set(None);
            action_error.set(None);
            snapshot.set(None);
            tree_root.set(None);
            selected_dir_id.set(None);
            current_path.set("\\".to_string());
            dir_entries.set(Vec::new());
            dir_loading.set(false);
            dir_error.set(None);
            context_menu.set(None);
            selected_entry.set(None);

            spawn(async move {
                let opened = tokio::task::spawn_blocking(move || open_ntfs_image(path)).await;
                match opened {
                    Ok(Ok(s)) => snapshot.set(Some(s)),
                    Ok(Err(e)) => snapshot_error.set(Some(e)),
                    Err(e) => snapshot_error.set(Some(format!("open task failed: {e}"))),
                }
                snapshot_loading.set(false);
            });
        })
    };

    let on_open_mft_path = {
        let open_path = open_path.to_owned();
        let mut snapshot = snapshot;
        let mut snapshot_error = snapshot_error;
        let mut snapshot_loading = snapshot_loading;
        let mut action_error = action_error;
        let mut tree_root = tree_root;
        let mut selected_dir_id = selected_dir_id;
        let mut current_path = current_path;
        let mut dir_entries = dir_entries;
        let mut dir_loading = dir_loading;
        let mut dir_error = dir_error;
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;

        Callback::new(move |(): ()| {
            let raw = open_path.read().trim().to_string();
            if raw.is_empty() {
                snapshot_error.set(Some(
                    "Enter a path to an $MFT snapshot file (often named `MFT`).".to_string(),
                ));
                return;
            }
            let path = PathBuf::from(raw);

            snapshot_loading.set(true);
            snapshot_error.set(None);
            action_error.set(None);
            snapshot.set(None);
            tree_root.set(None);
            selected_dir_id.set(None);
            current_path.set("\\".to_string());
            dir_entries.set(Vec::new());
            dir_loading.set(false);
            dir_error.set(None);
            context_menu.set(None);
            selected_entry.set(None);

            spawn(async move {
                let opened = tokio::task::spawn_blocking(move || open_mft_snapshot(path)).await;
                match opened {
                    Ok(Ok(s)) => snapshot.set(Some(s)),
                    Ok(Err(e)) => snapshot_error.set(Some(e)),
                    Err(e) => snapshot_error.set(Some(format!("open task failed: {e}"))),
                }
                snapshot_loading.set(false);
            });
        })
    };

    // Initialize explorer state when snapshot loads
    {
        let snapshot = snapshot.to_owned();
        let mut tree_root = tree_root;
        let mut selected_dir_id = selected_dir_id;
        let mut current_path = current_path;
        let mut dir_entries = dir_entries;
        let mut dir_loading = dir_loading;
        let mut dir_error = dir_error;
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;

        use_effect(move || {
            let snap = snapshot.read().clone();
            match snap {
                None => {
                    tree_root.set(None);
                    selected_dir_id.set(None);
                    current_path.set("\\".to_string());
                    dir_entries.set(Vec::new());
                    dir_loading.set(false);
                    dir_error.set(None);
                    context_menu.set(None);
                    selected_entry.set(None);
                }
                Some(s) => {
                    // Root directory is MFT entry 5.
                    let root = TreeNode {
                        name: "\\".to_string(),
                        entry_id: 5,
                        path: "\\".to_string(),
                        is_deleted: false,
                        expanded: true,
                        children_loaded: false,
                        children_loading: true,
                        children: Vec::new(),
                    };
                    tree_root.set(Some(root));
                    selected_dir_id.set(Some(5));
                    current_path.set("\\".to_string());
                    selected_entry.set(None);

                    let backend_tree = s.backend.clone();

                    // Load root child directories for the tree.
                    {
                        let mut tree_root = tree_root;
                        spawn(async move {
                            let res = tokio::task::spawn_blocking(move || {
                                load_child_dirs(backend_tree, 5, "\\")
                            })
                            .await;
                            let children = match res {
                                Ok(Ok(v)) => v,
                                Ok(Err(e)) => {
                                    tracing::warn!(target="ntfs_explorer.tree", error=%e, "load root tree failed");
                                    Vec::new()
                                }
                                Err(e) => {
                                    tracing::warn!(target="ntfs_explorer.tree", error=%e, "load root tree task failed");
                                    Vec::new()
                                }
                            };
                            if let Some(root) = tree_root.write().as_mut() {
                                root.children = children;
                                root.children_loaded = true;
                                root.children_loading = false;
                            }
                        });
                    }

                    // Load root directory entries for the details view.
                    {
                        let backend = s.backend.clone();
                        let mut dir_entries = dir_entries;
                        let mut dir_loading = dir_loading;
                        let mut dir_error = dir_error;
                        dir_loading.set(true);
                        dir_error.set(None);
                        spawn(async move {
                            let res =
                                tokio::task::spawn_blocking(move || load_dir_listing(backend, 5))
                                    .await;
                            match res {
                                Ok(Ok(v)) => dir_entries.set(v),
                                Ok(Err(e)) => dir_error.set(Some(e)),
                                Err(e) => dir_error.set(Some(format!("list task failed: {e}"))),
                            }
                            dir_loading.set(false);
                        });
                    }
                }
            }
        });
    }

    // Callbacks
    let on_select_dir = {
        let snapshot = snapshot.to_owned();
        let mut selected_dir_id = selected_dir_id;
        let mut current_path = current_path;
        let mut dir_entries = dir_entries;
        let mut dir_loading = dir_loading;
        let mut dir_error = dir_error;
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;
        Callback::new(move |(dir_entry_id, path): (u64, String)| {
            let Some(s) = snapshot.read().clone() else {
                return;
            };

            selected_dir_id.set(Some(dir_entry_id));
            current_path.set(path);
            context_menu.set(None);
            selected_entry.set(None);

            let backend = s.backend.clone();
            dir_loading.set(true);
            dir_error.set(None);
            spawn(async move {
                let res =
                    tokio::task::spawn_blocking(move || load_dir_listing(backend, dir_entry_id))
                        .await;
                match res {
                    Ok(Ok(v)) => dir_entries.set(v),
                    Ok(Err(e)) => dir_error.set(Some(e)),
                    Err(e) => dir_error.set(Some(format!("list task failed: {e}"))),
                }
                dir_loading.set(false);
            });
        })
    };

    let on_navigate_to_path = {
        let snapshot = snapshot.to_owned();
        Callback::new(move |path: String| {
            let Some(s) = snapshot.read().clone() else {
                return;
            };

            let backend = s.backend.clone();
            spawn(async move {
                let path2 = path.clone();
                let res = tokio::task::spawn_blocking(move || match backend {
                    SnapshotBackend::Ntfs(fs) => {
                        if path2 == "\\" {
                            Ok(5_u64)
                        } else {
                            fs.resolve_path_including_deleted(path2.as_str())
                                .map_err(|e| e.to_string())
                        }
                    }
                    SnapshotBackend::MftOnly(snap) => {
                        snap.resolve_dir_path_including_deleted(&path2)
                    }
                })
                .await;

                match res {
                    Ok(Ok(id)) => on_select_dir.call((id, path)),
                    Ok(Err(_e)) => on_select_dir.call((5, "\\".to_string())),
                    Err(_e) => on_select_dir.call((5, "\\".to_string())),
                }
            });
        })
    };

    let on_navigate_up = {
        let current_path = current_path.to_owned();
        Callback::new(move |(): ()| {
            let path = current_path.read().clone();
            if path == "\\" {
                return;
            }
            // Find parent path
            let parent = if let Some(idx) = path.rfind('\\') {
                if idx == 0 {
                    "\\".to_string()
                } else {
                    path[..idx].to_string()
                }
            } else {
                "\\".to_string()
            };

            on_navigate_to_path.call(parent);
        })
    };

    let on_clear_selection = {
        let mut context_menu = context_menu;
        let mut selected_entry = selected_entry;
        Callback::new(move |(): ()| {
            context_menu.set(None);
            selected_entry.set(None);
        })
    };

    let on_toggle_tree = {
        let snapshot = snapshot.to_owned();
        let mut tree_root = tree_root;
        Callback::new(move |dir_entry_id: u64| {
            let Some(s) = snapshot.read().clone() else {
                return;
            };
            let backend = s.backend.clone();

            let (should_load, parent_path) = {
                let mut root_opt = tree_root.write();
                let Some(root) = root_opt.as_mut() else {
                    return;
                };
                let Some(node) = root.find_mut(dir_entry_id) else {
                    return;
                };
                node.expanded = !node.expanded;
                if node.expanded && !node.children_loaded && !node.children_loading {
                    node.children_loading = true;
                    (true, node.path.clone())
                } else {
                    (false, String::new())
                }
            };

            if !should_load {
                return;
            }

            let mut tree_root2 = tree_root;
            spawn(async move {
                let res = tokio::task::spawn_blocking(move || {
                    load_child_dirs(backend, dir_entry_id, &parent_path)
                })
                .await;
                let children = match res {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        tracing::warn!(target="ntfs_explorer.tree", error=%e, "load tree children failed");
                        Vec::new()
                    }
                    Err(e) => {
                        tracing::warn!(target="ntfs_explorer.tree", error=%e, "load tree children task failed");
                        Vec::new()
                    }
                };
                let mut root_opt = tree_root2.write();
                if let Some(node) = root_opt
                    .as_mut()
                    .and_then(|root| root.find_mut(dir_entry_id))
                {
                    node.children = children;
                    node.children_loaded = true;
                    node.children_loading = false;
                }
            });
        })
    };

    let on_show_context_menu = {
        let mut context_menu = context_menu;
        Callback::new(move |state: ContextMenuState| context_menu.set(Some(state)))
    };

    let on_hide_context_menu = {
        let mut context_menu = context_menu;
        Callback::new(move |(): ()| context_menu.set(None))
    };

    #[cfg(feature = "desktop")]
    let on_save_as = {
        let snapshot = snapshot.to_owned();
        let mut action_error = action_error;
        let mut context_menu = context_menu;
        Callback::new(move |row: EntryRow| {
            let Some(s) = snapshot.read().clone() else {
                return;
            };
            if row.is_dir {
                return;
            }

            context_menu.set(None);
            action_error.set(None);

            let backend = s.backend.clone();
            if !backend.can_export() {
                action_error.set(Some(
                    "Export is not available for MFT-only snapshots (metadata-only mode)."
                        .to_string(),
                ));
                return;
            }
            spawn(async move {
                let Some(handle) = rfd::AsyncFileDialog::new()
                    .set_file_name(&row.name)
                    .save_file()
                    .await
                else {
                    return;
                };
                let out_path = handle.path().to_path_buf();

                let entry_id = row.entry_id;
                let res = tokio::task::spawn_blocking(move || {
                    export_file_default_stream(backend, entry_id, out_path)
                })
                .await;
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => action_error.set(Some(e)),
                    Err(e) => action_error.set(Some(format!("export task failed: {e}"))),
                }
            });
        })
    };

    #[cfg(feature = "liveview")]
    let on_save_as = {
        let mut action_error = action_error;
        let mut context_menu = context_menu;
        Callback::new(move |_row: EntryRow| {
            context_menu.set(None);
            action_error.set(Some(
                "Export is not implemented in LiveView yet (it runs on the server). Use the desktop build for now."
                    .to_string(),
            ));
        })
    };

    #[cfg(feature = "web")]
    let on_save_as = {
        let mut action_error = action_error;
        Callback::new(move |_row: EntryRow| {
            action_error.set(Some(
                "File export is not available in the web version.".to_string(),
            ));
        })
    };

    let on_select_entry = {
        let mut selected_entry = selected_entry;
        let mut context_menu = context_menu;
        Callback::new(move |row: EntryRow| {
            selected_entry.set(Some((row.entry_id, row.name.clone())));
            // Explorer-style: clicking elsewhere dismisses context menus.
            context_menu.set(None);
        })
    };

    let on_persist_ui_state = {
        let ui_state = ui_state.to_owned();
        Callback::new(move |(): ()| {
            let state = ui_state.read().clone();
            spawn(async move {
                let res = tokio::task::spawn_blocking(move || settings::save_ui_state(state)).await;
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(target="ntfs_explorer.ui_state", error=%e, "save ui state failed");
                    }
                    Err(e) => {
                        tracing::warn!(target="ntfs_explorer.ui_state", error=%e, "save ui state task failed");
                    }
                }
            });
        })
    };

    let on_set_col_modified_px = {
        let mut ui_state = ui_state;
        Callback::new(move |px: i32| ui_state.write().col_modified_px = px.clamp(90, 420))
    };
    let on_set_col_type_px = {
        let mut ui_state = ui_state;
        Callback::new(move |px: i32| ui_state.write().col_type_px = px.clamp(90, 420))
    };
    let on_set_col_size_px = {
        let mut ui_state = ui_state;
        Callback::new(move |px: i32| ui_state.write().col_size_px = px.clamp(90, 420))
    };

    // Resizing: left navigation pane width.
    let on_nav_resize_start = {
        let ui_state = ui_state.to_owned();
        let mut nav_resize = nav_resize;
        Callback::new(move |e: MouseEvent| {
            e.prevent_default();
            let x = e.client_coordinates().x;
            nav_resize.set(Some(NavResizeState {
                start_x: x,
                start_width_px: ui_state.read().nav_width_px.clamp(220, 520),
            }));
        })
    };
    let on_nav_resize_move = {
        let nav_resize = nav_resize.to_owned();
        let mut ui_state = ui_state;
        Callback::new(move |e: MouseEvent| {
            let Some(state) = *nav_resize.read() else {
                return;
            };
            let x = e.client_coordinates().x;
            let delta = x - state.start_x;
            let next = (state.start_width_px as f64 + delta).round() as i32;
            let next = next.clamp(220, 520);
            ui_state.write().nav_width_px = next;
        })
    };
    let on_nav_resize_end = {
        let mut nav_resize = nav_resize;
        Callback::new(move |_e: MouseEvent| {
            nav_resize.set(None);
            on_persist_ui_state.call(());
        })
    };

    // Computed values
    let theme_class = theme.read().to_string();
    let snapshot_path = snapshot
        .read()
        .as_ref()
        .map(|s| s.path.display().to_string());
    let is_mft_only = snapshot
        .read()
        .as_ref()
        .is_some_and(|s| s.backend.is_mft_only());
    let can_export = snapshot
        .read()
        .as_ref()
        .is_some_and(|s| s.backend.can_export());
    let entries_now = dir_entries.read().clone();
    let (items_total, items_deleted, items_encrypted) = {
        let total = entries_now.len();
        let deleted = entries_now.iter().filter(|e| e.is_deleted).count();
        let encrypted = entries_now.iter().filter(|e| e.efs_encrypted).count();
        (total, deleted, encrypted)
    };
    let can_go_up = current_path.read().as_str() != "\\";
    let nav_width_px = ui_state.read().nav_width_px.clamp(220, 520);
    let col_modified_px = ui_state.read().col_modified_px.clamp(90, 420);
    let col_type_px = ui_state.read().col_type_px.clamp(90, 420);
    let col_size_px = ui_state.read().col_size_px.clamp(90, 420);
    let selected_entry_now = selected_entry.read().clone();

    rsx! {
        // Stylesheets
        //
        // - Desktop/Web: load via the asset pipeline (`asset!()`).
        // - LiveView: inline CSS (the default LiveView axum adapter doesn't serve static assets).
        if cfg!(feature = "liveview") {
            style { "{styles::INLINE_CSS}" }
        } else {
            for sheet in styles::stylesheets().iter().copied() {
                document::Stylesheet { href: sheet.href }
            }
        }

        div { class: "app {theme_class}",
            // Toolbar
            Toolbar {
                snapshot_path,
                is_loading: *snapshot_loading.read(),
                is_mft_only,
            }

            // LiveView runs without a native menubar, so provide a path-based "open" flow.
            if cfg!(feature = "liveview") {
                div {
                    style: "display:flex; gap:8px; align-items:center; padding:8px 12px; border-bottom:1px solid rgba(0,0,0,0.08);",
                    span { style: "opacity:0.8; font-size:12px;", "Open path:" }
                    input {
                        r#type: "text",
                        placeholder: "/path/to/image.E01 or /path/to/MFT",
                        value: "{open_path.read()}",
                        style: "flex:1; min-width: 240px;",
                        oninput: move |e| open_path.set(e.value()),
                    }
                    button {
                        disabled: *snapshot_loading.read(),
                        onclick: move |_| on_open_image_path.call(()),
                        "Open image"
                    }
                    button {
                        disabled: *snapshot_loading.read(),
                        onclick: move |_| on_open_mft_path.call(()),
                        "Open MFT"
                    }
                    if snapshot.read().is_some() {
                        button {
                            disabled: *snapshot_loading.read(),
                            onclick: move |_| on_close_snapshot.call(()),
                            "Close"
                        }
                    }
                }
            }

            // Error banners
            if let Some(err) = snapshot_error.read().as_ref() {
                div { class: "error-banner", "{err}" }
            }
            if let Some(err) = action_error.read().as_ref() {
                div { class: "error-banner", "{err}" }
            }

            // Address bar
            AddressBar {
                path: current_path.read().clone(),
                on_navigate_up,
                on_navigate_to_path,
                can_go_up,
            }

            // Main content area (nav pane + details)
            div { class: "main-content",
                div { style: "width: {nav_width_px}px;",
                    NavigationPane {
                        tree_root: tree_root.read().clone(),
                        selected_path: current_path.read().clone(),
                        on_toggle: on_toggle_tree,
                        on_select: on_select_dir,
                    }
                }

                ResizeHandle {
                    active: nav_resize.read().is_some(),
                    on_start: on_nav_resize_start,
                }

                DetailsView {
                    entries: entries_now,
                    base_path: current_path.read().clone(),
                    is_loading: *dir_loading.read(),
                    error: dir_error.read().clone(),
                    has_snapshot: snapshot.read().is_some(),
                    selected: selected_entry_now,
                    col_modified_px,
                    col_type_px,
                    col_size_px,
                    on_set_col_modified_px,
                    on_set_col_type_px,
                    on_set_col_size_px,
                    on_persist_layout: on_persist_ui_state,
                    on_navigate_up,
                    on_clear_selection,
                    on_select_dir,
                    on_select_entry,
                    on_show_context_menu,
                }
            }

            if nav_resize.read().is_some() {
                ResizeOverlay {
                    on_move: on_nav_resize_move,
                    on_end: on_nav_resize_end,
                }
            }

            // Context menu overlay
            ContextMenu {
                state: context_menu.read().clone(),
                on_close: on_hide_context_menu,
                on_save_as,
                can_export,
            }

            // Status bar
            StatusBar {
                items_total,
                items_deleted,
                items_encrypted,
                selected_dir_id: *selected_dir_id.read(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background task helpers
// ---------------------------------------------------------------------------

fn open_ntfs_volume_auto(
    img: Arc<dyn ntfs::image::ReadAt>,
) -> Result<ntfs::ntfs::volume::Volume, String> {
    fn read_sector(img: &Arc<dyn ntfs::image::ReadAt>, offset: u64) -> Result<[u8; 512], String> {
        let mut buf = [0u8; 512];
        img.read_exact_at(offset, &mut buf)
            .map_err(|e| format!("read sector @ 0x{offset:x}: {e}"))?;
        Ok(buf)
    }

    fn oem_id(sector: &[u8; 512]) -> String {
        let raw = &sector[3..11];
        String::from_utf8_lossy(raw)
            .trim_matches(['\0', ' '])
            .to_string()
    }

    fn is_mbr(sector: &[u8; 512]) -> bool {
        sector[510] == 0x55 && sector[511] == 0xaa
    }

    fn parse_mbr_partitions(sector: &[u8; 512]) -> Vec<(usize, u8, u32, u32)> {
        let mut out = Vec::new();
        let pt = &sector[446..446 + 64];
        for i in 0..4 {
            let e = &pt[i * 16..(i + 1) * 16];
            let ptype = e[4];
            let start_lba = u32::from_le_bytes(e[8..12].try_into().expect("len=4"));
            let sectors = u32::from_le_bytes(e[12..16].try_into().expect("len=4"));
            if ptype == 0 || start_lba == 0 || sectors == 0 {
                continue;
            }
            out.push((i, ptype, start_lba, sectors));
        }
        out
    }

    // 1) Fast path: try offset 0.
    let open0 = ntfs::ntfs::volume::Volume::open(img.clone(), 0);
    if let Ok(v) = open0 {
        return Ok(v);
    }
    let open0_err = open0.unwrap_err().to_string();

    // 2) Heuristic: check if this looks like an MBR-partitioned disk, and try partition starts.
    let sector0 = read_sector(&img, 0)?;
    let mut notes: Vec<String> = Vec::new();
    notes.push(format!("offset 0 OEM={}", oem_id(&sector0)));

    if is_mbr(&sector0) {
        let parts = parse_mbr_partitions(&sector0);
        if parts.is_empty() {
            notes
                .push("MBR signature present but no non-empty partition entries found".to_string());
        }

        for (idx, ptype, start_lba, sectors) in parts {
            let part_offset = u64::from(start_lba)
                .checked_mul(512)
                .ok_or_else(|| "partition offset overflow".to_string())?;
            let boot = read_sector(&img, part_offset)?;
            let oem = oem_id(&boot);
            notes.push(format!(
                "MBR partition {idx}: type=0x{ptype:02x} start_lba={start_lba} sectors={sectors} offset=0x{part_offset:x} OEM={oem}"
            ));

            // Only attempt to open candidates that actually look like NTFS.
            if &boot[3..11] != b"NTFS    " {
                continue;
            }
            if let Ok(v) = ntfs::ntfs::volume::Volume::open(img.clone(), part_offset) {
                return Ok(v);
            }
        }
    }

    // If we got here, we failed to locate an NTFS volume.
    let mut msg = String::new();
    msg.push_str(&format!("{open0_err}\n"));
    msg.push_str("This image does not appear to contain an NTFS volume that this tool can open.\n");
    msg.push_str("Diagnostics:\n");
    for n in notes {
        msg.push_str(&format!("- {n}\n"));
    }
    Err(msg)
}

fn open_ntfs_image(path: PathBuf) -> Result<LoadedSnapshot, String> {
    let img = ntfs::image::Image::open(&path).map_err(|e| format!("open image: {e}"))?;
    let img: Arc<dyn ntfs::image::ReadAt> = Arc::new(img);

    let volume = open_ntfs_volume_auto(img).map_err(|e| format!("open NTFS volume: {e}"))?;
    let fs = ntfs::ntfs::filesystem::FileSystem::new(volume);

    Ok(LoadedSnapshot {
        path,
        backend: SnapshotBackend::Ntfs(fs),
    })
}

fn open_mft_snapshot(path: PathBuf) -> Result<LoadedSnapshot, String> {
    let snap = mft_only::MftOnlySnapshot::open(&path)?;
    Ok(LoadedSnapshot {
        path,
        backend: SnapshotBackend::MftOnly(snap),
    })
}

fn load_child_dirs(
    backend: SnapshotBackend,
    dir_entry_id: u64,
    parent_path: &str,
) -> Result<Vec<TreeNode>, String> {
    match backend {
        SnapshotBackend::Ntfs(fs) => {
            let entries = fs
                .read_dir_including_deleted(dir_entry_id)
                .map_err(|e| e.to_string())?;
            let mut out = Vec::new();

            for e in entries {
                if is_dot_dir_entry(e.name.as_str()) {
                    continue;
                }
                let entry = fs
                    .volume()
                    .read_mft_entry(e.entry_id)
                    .map_err(|err| err.to_string())?;
                if should_hide_dos_alias(&entry, dir_entry_id, e.name.as_str()) {
                    continue;
                }
                if !entry.is_dir() {
                    continue;
                }
                let allocated = entry
                    .header
                    .flags
                    .contains(mft::entry::EntryFlags::ALLOCATED);
                let child_path = join_ntfs_child_path(parent_path, e.name.as_str());
                out.push(TreeNode {
                    name: e.name,
                    entry_id: e.entry_id,
                    path: child_path,
                    is_deleted: !allocated,
                    expanded: false,
                    children_loaded: false,
                    children_loading: false,
                    children: Vec::new(),
                });
            }

            out.sort_by(|a, b| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            });
            Ok(out)
        }
        SnapshotBackend::MftOnly(snap) => {
            let entries = snap.list_children(dir_entry_id);
            let mut out = Vec::new();

            for e in entries {
                if is_dot_dir_entry(e.name.as_str()) {
                    continue;
                }
                let Some(meta) = snap.entry_meta(e.entry_id) else {
                    continue;
                };
                if !meta.is_dir {
                    continue;
                }

                let child_path = join_ntfs_child_path(parent_path, e.name.as_str());
                out.push(TreeNode {
                    name: e.name,
                    entry_id: e.entry_id,
                    path: child_path,
                    is_deleted: !meta.is_allocated,
                    expanded: false,
                    children_loaded: false,
                    children_loading: false,
                    children: Vec::new(),
                });
            }

            out.sort_by(|a, b| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            });
            Ok(out)
        }
    }
}

fn load_dir_listing(backend: SnapshotBackend, dir_entry_id: u64) -> Result<Vec<EntryRow>, String> {
    match backend {
        SnapshotBackend::Ntfs(fs) => {
            let entries = fs
                .read_dir_including_deleted(dir_entry_id)
                .map_err(|e| e.to_string())?;

            let mut out = Vec::with_capacity(entries.len());
            for e in entries {
                if is_dot_dir_entry(e.name.as_str()) {
                    continue;
                }
                let entry = fs
                    .volume()
                    .read_mft_entry(e.entry_id)
                    .map_err(|err| err.to_string())?;
                if should_hide_dos_alias(&entry, dir_entry_id, e.name.as_str()) {
                    continue;
                }
                let is_dir = entry.is_dir();
                let allocated = entry
                    .header
                    .flags
                    .contains(mft::entry::EntryFlags::ALLOCATED);
                let efs_encrypted = is_entry_efs_encrypted(&entry);
                let (size_bytes, modified_unix_s) = entry
                    .find_best_name_attribute()
                    .map(|n| (n.logical_size, n.modified.as_second()))
                    .unwrap_or((0, 0));
                out.push(EntryRow {
                    name: e.name,
                    entry_id: e.entry_id,
                    is_dir,
                    is_deleted: !allocated,
                    efs_encrypted,
                    size_bytes: if is_dir { 0 } else { size_bytes },
                    modified_unix_s,
                });
            }

            out.sort_by(|a, b| match (a.is_dir, b.is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a
                    .name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase()),
            });
            Ok(out)
        }
        SnapshotBackend::MftOnly(snap) => {
            let entries = snap.list_children(dir_entry_id);
            let mut out = Vec::with_capacity(entries.len());

            for e in entries {
                if is_dot_dir_entry(e.name.as_str()) {
                    continue;
                }
                let Some(meta) = snap.entry_meta(e.entry_id) else {
                    continue;
                };

                out.push(EntryRow {
                    name: e.name,
                    entry_id: e.entry_id,
                    is_dir: meta.is_dir,
                    is_deleted: !meta.is_allocated,
                    efs_encrypted: meta.efs_encrypted,
                    size_bytes: if meta.is_dir { 0 } else { e.logical_size },
                    modified_unix_s: e.modified_unix_s,
                });
            }

            out.sort_by(|a, b| match (a.is_dir, b.is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a
                    .name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase()),
            });
            Ok(out)
        }
    }
}

/// Hide the DOS 8.3 alias (`SYSTEM~1`) when a Win32 long name exists for the same parent dir.
///
/// This matches the default Windows Explorer behavior (it does not show 8.3 aliases as separate
/// directory entries).
fn should_hide_dos_alias(entry: &mft::MftEntry, parent_dir_id: u64, dir_entry_name: &str) -> bool {
    use mft::attribute::MftAttributeType;
    use mft::attribute::x30::FileNamespace;

    let mut has_win32 = false;
    let mut is_this_dos = false;
    for attr in entry
        .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
        .filter_map(std::result::Result::ok)
    {
        let Some(fname) = attr.data.into_file_name() else {
            continue;
        };
        if fname.parent.entry != parent_dir_id {
            continue;
        }

        if matches!(
            fname.namespace,
            FileNamespace::Win32 | FileNamespace::Win32AndDos
        ) {
            has_win32 = true;
        }
        if fname.name == dir_entry_name && fname.namespace == FileNamespace::DOS {
            is_this_dos = true;
        }
    }

    is_this_dos && has_win32
}

fn is_entry_efs_encrypted(entry: &mft::MftEntry) -> bool {
    for attr in entry
        .iter_attributes_matching(Some(vec![
            mft::attribute::MftAttributeType::StandardInformation,
        ]))
        .filter_map(std::result::Result::ok)
    {
        if let Some(si) = attr.data.into_standard_info()
            && si
                .file_flags
                .contains(mft::attribute::FileAttributeFlags::FILE_ATTRIBUTE_ENCRYPTED)
        {
            return true;
        }
    }
    false
}

#[cfg(feature = "desktop")]
fn export_file_default_stream(
    backend: SnapshotBackend,
    entry_id: u64,
    out_path: PathBuf,
) -> Result<(), String> {
    match backend {
        SnapshotBackend::Ntfs(fs) => fs
            .export_file_default_stream_to_path(entry_id, &out_path)
            .map_err(|e| format!("export $DATA: {e}")),
        SnapshotBackend::MftOnly(_) => Err(
            "export is not available for MFT-only snapshots (no NTFS cluster access)".to_string(),
        ),
    }
}
