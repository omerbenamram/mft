use dioxus::prelude::*;

use crate::icons;

#[linkme::distributed_slice(crate::styles::STYLESHEETS)]
static NAVIGATION_PANE_CSS: crate::styles::Stylesheet = crate::styles::Stylesheet {
    order: 200,
    name: "components/navigation_pane",
    href: asset!("/src/components/navigation_pane.css"),
};

/// A node in the folder tree.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeNode {
    pub name: String,
    pub entry_id: u64,
    pub path: String,
    pub is_deleted: bool,
    pub expanded: bool,
    pub children_loaded: bool,
    pub children_loading: bool,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    pub fn find_mut(&mut self, entry_id: u64) -> Option<&mut TreeNode> {
        if self.entry_id == entry_id {
            return Some(self);
        }
        for c in &mut self.children {
            if let Some(hit) = c.find_mut(entry_id) {
                return Some(hit);
            }
        }
        None
    }
}

#[component]
pub fn NavigationPane(
    tree_root: Option<TreeNode>,
    selected_path: String,
    on_toggle: Callback<u64>,
    on_select: Callback<(u64, String)>,
) -> Element {
    rsx! {
        div { class: "nav-pane",
            div { class: "nav-pane-header",
                span { class: "nav-pane-title", "Folders" }
            }

            div { class: "nav-pane-body",
                if let Some(root) = tree_root {
                    {render_tree(&root, selected_path.as_str(), on_toggle, on_select)}
                } else {
                    div { class: "empty-state",
                        span { class: "empty-state-icon", {icons::empty_folder_large()} }
                        span { class: "empty-state-title", "No snapshot loaded" }
                        span { class: "empty-state-subtitle", "Open an NTFS image to browse" }
                    }
                }
            }
        }
    }
}

fn render_tree(
    root: &TreeNode,
    selected_path: &str,
    on_toggle: Callback<u64>,
    on_select: Callback<(u64, String)>,
) -> Element {
    let mut rows: Vec<(TreeNode, usize)> = Vec::new();
    collect_tree_rows(root, 0, &mut rows);

    rsx! {
        div { class: "tree",
            for (node, depth) in rows {
                TreeRow {
                    // Use path as key since entry_id can repeat for deleted/hard-linked items
                    key: "{node.path}",
                    node: node.clone(),
                    depth,
                    selected: node.path == selected_path,
                    on_toggle,
                    on_select,
                }
            }
        }
    }
}

fn collect_tree_rows(node: &TreeNode, depth: usize, out: &mut Vec<(TreeNode, usize)>) {
    out.push((node.clone(), depth));
    if node.expanded {
        for c in &node.children {
            collect_tree_rows(c, depth + 1, out);
        }
    }
}

#[component]
fn TreeRow(
    node: TreeNode,
    depth: usize,
    selected: bool,
    on_toggle: Callback<u64>,
    on_select: Callback<(u64, String)>,
) -> Element {
    let has_children = !node.children_loaded || !node.children.is_empty();

    let mut row_class = String::from("tree-row");
    if selected {
        row_class.push_str(" is-selected");
    }
    if node.is_deleted {
        row_class.push_str(" is-deleted");
    }

    let indent_px = (depth as i32) * 20;
    let entry_id = node.entry_id;
    let path = node.path.clone();
    let name = node.name.clone();

    rsx! {
        div {
            class: "{row_class}",
            style: "padding-left: {indent_px}px;",
            onclick: move |_| on_select.call((entry_id, path.clone())),

            // Expand/collapse chevron
            if has_children {
                button {
                    class: "tree-chevron",
                    onclick: move |e| {
                        e.stop_propagation();
                        on_toggle.call(entry_id);
                    },
                    if node.children_loading {
                        span { class: "tree-spinner" }
                    } else if node.expanded {
                        span { class: "tree-chevron-icon is-expanded", {icons::chevron_down()} }
                    } else {
                        span { class: "tree-chevron-icon", {icons::chevron_right()} }
                    }
                }
            } else {
                span { class: "tree-chevron-placeholder" }
            }

            // Folder icon
            span {
                class: if node.is_deleted { "tree-icon is-deleted" } else { "tree-icon" },
                if node.is_deleted {
                    {icons::folder_deleted()}
                } else if node.expanded {
                    {icons::folder_open()}
                } else {
                    {icons::folder_closed()}
                }
            }

            // Name
            span { class: "tree-name", "{name}" }

            // Deleted badge
            if node.is_deleted {
                span { class: "tree-badge is-deleted", "DEL" }
            }
        }
    }
}
