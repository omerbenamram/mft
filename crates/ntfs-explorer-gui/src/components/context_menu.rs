use dioxus::prelude::*;

use crate::components::EntryRow;
use crate::icons;

#[linkme::distributed_slice(crate::styles::STYLESHEETS)]
static CONTEXT_MENU_CSS: crate::styles::Stylesheet = crate::styles::Stylesheet {
    order: 300,
    name: "components/context_menu",
    href: asset!("/src/components/context_menu.css"),
};

/// State for the context menu popup.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextMenuState {
    pub x: f64,
    pub y: f64,
    pub row: EntryRow,
}

#[component]
pub fn ContextMenu(
    state: Option<ContextMenuState>,
    on_close: Callback<()>,
    on_save_as: Callback<EntryRow>,
    can_export: bool,
) -> Element {
    let Some(cm) = state else {
        return VNode::empty();
    };

    let pos = format!("left: {}px; top: {}px;", cm.x, cm.y);
    let row = cm.row.clone();
    let is_dir = row.is_dir;
    let is_deleted = row.is_deleted;
    let is_encrypted = row.efs_encrypted;
    let export_disabled = is_dir || !can_export;

    rsx! {
        div {
            class: "context-overlay",
            onclick: move |_| on_close.call(()),
            oncontextmenu: move |e| e.prevent_default(),

            div {
                class: "context-menu",
                style: "{pos}",
                onclick: move |e| e.stop_propagation(),

                // Header with file info
                div { class: "context-header",
                    span { class: "context-icon",
                        if is_dir {
                            if is_deleted { {icons::folder_deleted()} } else { {icons::folder_closed()} }
                        } else if is_deleted {
                            {icons::file_deleted()}
                        } else {
                            {icons::file_generic()}
                        }
                    }
                    span { class: "context-name", "{row.name}" }
                }

                div { class: "context-divider" }

                // Menu items
                button {
                    class: "context-item",
                    disabled: export_disabled,
                    onclick: move |_| on_save_as.call(row.clone()),
                    span { class: "context-item-icon", {icons::download()} }
                    span { class: "context-item-text", "Save As…" }
                    if is_dir {
                        span { class: "context-item-hint", "(folders not supported)" }
                    } else if !can_export {
                        span { class: "context-item-hint", "(MFT-only mode)" }
                    }
                }

                if is_deleted || is_encrypted {
                    div { class: "context-divider" }

                    div { class: "context-info",
                        if is_deleted {
                            div { class: "context-info-row",
                                span { class: "context-info-icon is-deleted", {icons::deleted_badge()} }
                                span { class: "context-info-text", "This file has been deleted" }
                            }
                        }
                        if is_encrypted {
                            div { class: "context-info-row",
                                span { class: "context-info-icon is-encrypted", {icons::encrypted_badge()} }
                                span { class: "context-info-text", "EFS encrypted (raw export)" }
                            }
                        }
                    }
                }
            }
        }
    }
}
