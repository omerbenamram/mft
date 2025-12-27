use dioxus::prelude::*;

use crate::icons;

#[linkme::distributed_slice(crate::styles::STYLESHEETS)]
static TOOLBAR_CSS: crate::styles::Stylesheet = crate::styles::Stylesheet {
    order: 200,
    name: "components/toolbar",
    href: asset!("/src/components/toolbar.css"),
};

#[component]
pub fn Toolbar(snapshot_path: Option<String>, is_loading: bool, is_mft_only: bool) -> Element {
    rsx! {
        div { class: "toolbar",
            div { class: "toolbar-section toolbar-section-left",
                div { class: "toolbar-title",
                    span { class: "toolbar-icon", {icons::app_icon()} }
                    span { class: "toolbar-title-text", "NTFS Explorer" }
                }
            }

            div { class: "toolbar-section toolbar-section-center",
                if is_loading {
                    div { class: "toolbar-status is-loading",
                        span { class: "toolbar-spinner" }
                        span { "Loading…" }
                    }
                } else if let Some(path) = snapshot_path {
                    div { class: "toolbar-status",
                        span { class: "toolbar-status-icon",
                            if is_mft_only {
                                {icons::file_generic()}
                            } else {
                                {icons::hard_drive()}
                            }
                        }
                        span { class: "toolbar-status-path",
                            if is_mft_only {
                                "MFT snapshot • "
                            } else {
                                "NTFS image • "
                            }
                            "{path}"
                        }
                    }
                } else {
                    div { class: "toolbar-status is-muted",
                        span { "No snapshot loaded • Press " }
                        kbd { "Ctrl+O" }
                        span { " (image) or " }
                        kbd { "Ctrl+Shift+O" }
                        span { " (MFT)" }
                    }
                }
            }

            div { class: "toolbar-section toolbar-section-right",
                // Future: view toggle buttons, etc.
            }
        }
    }
}
