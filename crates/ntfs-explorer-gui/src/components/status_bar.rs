use dioxus::prelude::*;

#[linkme::distributed_slice(crate::styles::STYLESHEETS)]
static STATUS_BAR_CSS: crate::styles::Stylesheet = crate::styles::Stylesheet {
    order: 200,
    name: "components/status_bar",
    href: asset!("/src/components/status_bar.css"),
};

#[component]
pub fn StatusBar(
    items_total: usize,
    items_deleted: usize,
    items_encrypted: usize,
    selected_dir_id: Option<u64>,
) -> Element {
    rsx! {
        div { class: "status-bar",
            div { class: "status-left",
                span { class: "status-item",
                    span { class: "status-count", "{items_total}" }
                    span { class: "status-label", "items" }
                }

                if items_deleted > 0 {
                    span { class: "status-separator" }
                    span { class: "status-item is-deleted",
                        span { class: "status-count", "{items_deleted}" }
                        span { class: "status-label", "deleted" }
                    }
                }

                if items_encrypted > 0 {
                    span { class: "status-separator" }
                    span { class: "status-item is-encrypted",
                        span { class: "status-count", "{items_encrypted}" }
                        span { class: "status-label", "encrypted" }
                    }
                }
            }

            div { class: "status-right",
                if let Some(id) = selected_dir_id {
                    span { class: "status-item is-muted",
                        "MFT #{id}"
                    }
                }
            }
        }
    }
}
