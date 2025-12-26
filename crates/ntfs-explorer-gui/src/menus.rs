use dioxus::desktop::muda::accelerator::{Accelerator, CMD_OR_CTRL, Code, Modifiers};
use dioxus::desktop::muda::{Menu, MenuItem, PredefinedMenuItem, Submenu};

pub const MENU_OPEN_SNAPSHOT: &str = "file-open-snapshot";
pub const MENU_OPEN_MFT_SNAPSHOT: &str = "file-open-mft-snapshot";
pub const MENU_CLOSE_SNAPSHOT: &str = "file-close-snapshot";
pub const MENU_REFRESH: &str = "view-refresh";

pub fn build_menu() -> Menu {
    let menu = Menu::new();

    let file_menu = Submenu::new("File", true);
    file_menu
        .append_items(&[
            &MenuItem::with_id(
                MENU_OPEN_SNAPSHOT,
                "Open NTFS Image…",
                true,
                Some(Accelerator::new(Some(CMD_OR_CTRL), Code::KeyO)),
            ),
            &MenuItem::with_id(
                MENU_OPEN_MFT_SNAPSHOT,
                "Open MFT Snapshot…",
                true,
                Some(Accelerator::new(
                    Some(CMD_OR_CTRL | Modifiers::SHIFT),
                    Code::KeyO,
                )),
            ),
            &MenuItem::with_id(MENU_CLOSE_SNAPSHOT, "Close Snapshot", true, None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::quit(None),
        ])
        .expect("append File menu items");

    let view_menu = Submenu::new("View", true);
    view_menu
        .append_items(&[&MenuItem::with_id(
            MENU_REFRESH,
            "Refresh",
            true,
            Some(Accelerator::new(None, Code::F5)),
        )])
        .expect("append View menu items");

    let edit_menu = Submenu::new("Edit", true);
    edit_menu
        .append_items(&[
            &PredefinedMenuItem::undo(None),
            &PredefinedMenuItem::redo(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::cut(None),
            &PredefinedMenuItem::copy(None),
            &PredefinedMenuItem::paste(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::select_all(None),
        ])
        .expect("append Edit menu items");

    let window_menu = Submenu::new("Window", true);
    window_menu
        .append_items(&[
            &PredefinedMenuItem::fullscreen(None),
            &PredefinedMenuItem::maximize(None),
            &PredefinedMenuItem::minimize(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::close_window(None),
        ])
        .expect("append Window menu items");

    menu.append_items(&[&file_menu, &edit_menu, &view_menu, &window_menu])
        .expect("append menubar");

    menu
}
