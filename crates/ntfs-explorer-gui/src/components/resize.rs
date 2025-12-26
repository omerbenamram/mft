use dioxus::prelude::*;

#[linkme::distributed_slice(crate::styles::STYLESHEETS)]
static RESIZE_CSS: crate::styles::Stylesheet = crate::styles::Stylesheet {
    order: 250,
    name: "components/resize",
    href: asset!("/src/components/resize.css"),
};

#[component]
pub fn ResizeOverlay(on_move: Callback<MouseEvent>, on_end: Callback<MouseEvent>) -> Element {
    rsx! {
        div {
            class: "resize-overlay",
            onmousemove: move |e| on_move.call(e),
            onmouseup: move |e| on_end.call(e),
        }
    }
}

#[component]
pub fn ResizeHandle(active: bool, on_start: Callback<MouseEvent>) -> Element {
    let class = if active {
        "resize-handle is-active"
    } else {
        "resize-handle"
    };

    rsx! {
        div {
            class,
            onmousedown: move |e| on_start.call(e),
        }
    }
}
