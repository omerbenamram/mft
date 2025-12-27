use std::sync::LazyLock;

use dioxus::prelude::*;

#[derive(Clone, Copy)]
pub struct Stylesheet {
    pub order: u16,
    pub name: &'static str,
    pub href: Asset,
}

#[linkme::distributed_slice]
pub static STYLESHEETS: [Stylesheet] = [..];

static SORTED_STYLESHEETS: LazyLock<Vec<Stylesheet>> = LazyLock::new(|| {
    let mut sheets: Vec<Stylesheet> = STYLESHEETS.iter().copied().collect();
    sheets.sort_unstable_by(|a, b| (a.order, a.name).cmp(&(b.order, b.name)));
    sheets
});

pub fn stylesheets() -> &'static [Stylesheet] {
    SORTED_STYLESHEETS.as_slice()
}

// ---------------------------------------------------------------------------
// LiveView
// ---------------------------------------------------------------------------
//
// LiveView's default Axum adapter does not serve static assets (it uses a catch-all route that
// returns the LiveView HTML shell). Instead of relying on `asset!()` + `<link rel="stylesheet">`,
// inline the CSS so the UI renders correctly.
#[cfg(feature = "liveview")]
pub const INLINE_CSS: &str = concat!(
    include_str!("styles/tokens.css"),
    "\n",
    include_str!("styles/base.css"),
    "\n",
    // Components
    include_str!("components/toolbar.css"),
    "\n",
    include_str!("components/address_bar.css"),
    "\n",
    include_str!("components/navigation_pane.css"),
    "\n",
    include_str!("components/details_view.css"),
    "\n",
    include_str!("components/resize.css"),
    "\n",
    include_str!("components/context_menu.css"),
    "\n",
    include_str!("components/status_bar.css"),
    "\n",
);

#[cfg(not(feature = "liveview"))]
pub const INLINE_CSS: &str = "";

// ---------------------------------------------------------------------------
// Core stylesheets (tokens → base → components)
// ---------------------------------------------------------------------------

#[linkme::distributed_slice(STYLESHEETS)]
static TOKENS_STYLESHEET: Stylesheet = Stylesheet {
    order: 0,
    name: "styles/tokens",
    href: asset!("/src/styles/tokens.css"),
};

#[linkme::distributed_slice(STYLESHEETS)]
static BASE_STYLESHEET: Stylesheet = Stylesheet {
    order: 100,
    name: "styles/base",
    href: asset!("/src/styles/base.css"),
};
