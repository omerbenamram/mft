//! Windows 11 Fluent-style SVG icons
//!
//! These SVGs are inspired by the Windows 11 File Explorer iconography.

#![allow(dead_code)]

use dioxus::prelude::*;

/// Windows 11 style folder icon (closed)
pub fn folder_closed() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            // Folder back
            path {
                d: "M2 5.5C2 4.11929 3.11929 3 4.5 3H7.17157C7.70201 3 8.21071 3.21071 8.58579 3.58579L9.5 4.5H15.5C16.8807 4.5 18 5.61929 18 7V14.5C18 15.8807 16.8807 17 15.5 17H4.5C3.11929 17 2 15.8807 2 14.5V5.5Z",
                fill: "#DCBA6A",
            }
            // Folder front
            path {
                d: "M2 7.5C2 6.67157 2.67157 6 3.5 6H16.5C17.3284 6 18 6.67157 18 7.5V14.5C18 15.8807 16.8807 17 15.5 17H4.5C3.11929 17 2 15.8807 2 14.5V7.5Z",
                fill: "#F2D675",
            }
        }
    }
}

/// Windows 11 style folder icon (open)
pub fn folder_open() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            // Folder back
            path {
                d: "M2 5.5C2 4.11929 3.11929 3 4.5 3H7.17157C7.70201 3 8.21071 3.21071 8.58579 3.58579L9.5 4.5H15.5C16.8807 4.5 18 5.61929 18 7V8H4C2.89543 8 2 8.89543 2 10V5.5Z",
                fill: "#DCBA6A",
            }
            // Folder front (angled open)
            path {
                d: "M1 10C1 9.17157 1.67157 8.5 2.5 8.5H17.5C18.3284 8.5 19 9.17157 19 10L17.5 15.5C17.2239 16.3284 16.5523 17 15.5 17H4.5C3.44772 17 2.77614 16.3284 2.5 15.5L1 10Z",
                fill: "#F2D675",
            }
        }
    }
}

/// Windows 11 style folder icon (deleted/grayed)
pub fn folder_deleted() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            style: "opacity: 0.6;",
            path {
                d: "M2 5.5C2 4.11929 3.11929 3 4.5 3H7.17157C7.70201 3 8.21071 3.21071 8.58579 3.58579L9.5 4.5H15.5C16.8807 4.5 18 5.61929 18 7V14.5C18 15.8807 16.8807 17 15.5 17H4.5C3.11929 17 2 15.8807 2 14.5V5.5Z",
                fill: "#9A8866",
            }
            path {
                d: "M2 7.5C2 6.67157 2.67157 6 3.5 6H16.5C17.3284 6 18 6.67157 18 7.5V14.5C18 15.8807 16.8807 17 15.5 17H4.5C3.11929 17 2 15.8807 2 14.5V7.5Z",
                fill: "#B8A575",
            }
        }
    }
}

/// Windows 11 style generic file icon
pub fn file_generic() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            // Page body
            path {
                d: "M5 2C4.44772 2 4 2.44772 4 3V17C4 17.5523 4.44772 18 5 18H15C15.5523 18 16 17.5523 16 17V7L11 2H5Z",
                fill: "#FFFFFF",
                stroke: "#C4C4C4",
                stroke_width: "1",
            }
            // Folded corner
            path {
                d: "M11 2V6C11 6.55228 11.4477 7 12 7H16",
                stroke: "#C4C4C4",
                stroke_width: "1",
                fill: "none",
            }
            path {
                d: "M11 2L16 7H12C11.4477 7 11 6.55228 11 6V2Z",
                fill: "#E8E8E8",
            }
        }
    }
}

/// Windows 11 style file icon (deleted)
pub fn file_deleted() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            style: "opacity: 0.6;",
            path {
                d: "M5 2C4.44772 2 4 2.44772 4 3V17C4 17.5523 4.44772 18 5 18H15C15.5523 18 16 17.5523 16 17V7L11 2H5Z",
                fill: "#E8E8E8",
                stroke: "#AAAAAA",
                stroke_width: "1",
            }
            path {
                d: "M11 2V6C11 6.55228 11.4477 7 12 7H16",
                stroke: "#AAAAAA",
                stroke_width: "1",
                fill: "none",
            }
            path {
                d: "M11 2L16 7H12C11.4477 7 11 6.55228 11 6V2Z",
                fill: "#D0D0D0",
            }
        }
    }
}

/// Windows 11 style This PC / Computer icon
pub fn this_pc() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            // Monitor body
            path {
                d: "M2 4C2 3.44772 2.44772 3 3 3H17C17.5523 3 18 3.44772 18 4V12C18 12.5523 17.5523 13 17 13H3C2.44772 13 2 12.5523 2 12V4Z",
                fill: "#0078D4",
            }
            // Screen
            path {
                d: "M3 4.5H17V11.5H3V4.5Z",
                fill: "#50E6FF",
            }
            // Stand
            path {
                d: "M7 13H13V15H7V13Z",
                fill: "#505050",
            }
            // Base
            path {
                d: "M5 15H15V16C15 16.5523 14.5523 17 14 17H6C5.44772 17 5 16.5523 5 16V15Z",
                fill: "#707070",
            }
        }
    }
}

/// Windows 11 style hard drive icon
pub fn hard_drive() -> Element {
    rsx! {
        svg {
            width: "20",
            height: "20",
            view_box: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            // Drive body
            path {
                d: "M3 6C3 4.89543 3.89543 4 5 4H15C16.1046 4 17 4.89543 17 6V14C17 15.1046 16.1046 16 15 16H5C3.89543 16 3 15.1046 3 14V6Z",
                fill: "#E0E0E0",
                stroke: "#A0A0A0",
                stroke_width: "1",
            }
            // Activity LED
            circle {
                cx: "5.5",
                cy: "13.5",
                r: "1",
                fill: "#00CC6A",
            }
            // Label area
            rect {
                x: "5",
                y: "6",
                width: "10",
                height: "5",
                rx: "1",
                fill: "#F5F5F5",
            }
        }
    }
}

/// Navigation arrow: Up
pub fn arrow_up() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M8 3L13 8H10V13H6V8H3L8 3Z",
                fill: "currentColor",
            }
        }
    }
}

/// Navigation arrow: Back
pub fn arrow_back() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M10 3L5 8L10 13",
                stroke: "currentColor",
                stroke_width: "1.5",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                fill: "none",
            }
        }
    }
}

/// Navigation arrow: Forward
pub fn arrow_forward() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M6 3L11 8L6 13",
                stroke: "currentColor",
                stroke_width: "1.5",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                fill: "none",
            }
        }
    }
}

/// Chevron right (for tree expand)
pub fn chevron_right() -> Element {
    rsx! {
        svg {
            width: "12",
            height: "12",
            view_box: "0 0 12 12",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M4.5 2.5L8 6L4.5 9.5",
                stroke: "currentColor",
                stroke_width: "1.2",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                fill: "none",
            }
        }
    }
}

/// Chevron down (for tree collapse)
pub fn chevron_down() -> Element {
    rsx! {
        svg {
            width: "12",
            height: "12",
            view_box: "0 0 12 12",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M2.5 4.5L6 8L9.5 4.5",
                stroke: "currentColor",
                stroke_width: "1.2",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                fill: "none",
            }
        }
    }
}

/// Breadcrumb separator
pub fn breadcrumb_sep() -> Element {
    rsx! {
        svg {
            width: "8",
            height: "16",
            view_box: "0 0 8 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M2 4L6 8L2 12",
                stroke: "currentColor",
                stroke_width: "1.2",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                fill: "none",
            }
        }
    }
}

/// Download / Export icon
pub fn download() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M8 2V10M8 10L5 7M8 10L11 7",
                stroke: "currentColor",
                stroke_width: "1.5",
                stroke_linecap: "round",
                stroke_linejoin: "round",
            }
            path {
                d: "M3 13H13",
                stroke: "currentColor",
                stroke_width: "1.5",
                stroke_linecap: "round",
            }
        }
    }
}

/// Copy icon
pub fn copy() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            rect {
                x: "5",
                y: "5",
                width: "9",
                height: "9",
                rx: "1",
                stroke: "currentColor",
                stroke_width: "1.2",
                fill: "none",
            }
            path {
                d: "M11 5V3C11 2.44772 10.5523 2 10 2H3C2.44772 2 2 2.44772 2 3V10C2 10.5523 2.44772 11 3 11H5",
                stroke: "currentColor",
                stroke_width: "1.2",
                fill: "none",
            }
        }
    }
}

/// Info icon
pub fn info() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            circle {
                cx: "8",
                cy: "8",
                r: "6.5",
                stroke: "currentColor",
                stroke_width: "1.2",
                fill: "none",
            }
            path {
                d: "M8 7V11",
                stroke: "currentColor",
                stroke_width: "1.2",
                stroke_linecap: "round",
            }
            circle {
                cx: "8",
                cy: "5",
                r: "0.75",
                fill: "currentColor",
            }
        }
    }
}

/// Refresh icon
pub fn refresh() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 16 16",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M13 8C13 10.7614 10.7614 13 8 13C5.23858 13 3 10.7614 3 8C3 5.23858 5.23858 3 8 3C9.65685 3 11.1212 3.83579 12 5.10102",
                stroke: "currentColor",
                stroke_width: "1.5",
                stroke_linecap: "round",
                fill: "none",
            }
            path {
                d: "M12 2V5.5H8.5",
                stroke: "currentColor",
                stroke_width: "1.5",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                fill: "none",
            }
        }
    }
}

/// Deleted/Trash indicator
pub fn deleted_badge() -> Element {
    rsx! {
        svg {
            width: "12",
            height: "12",
            view_box: "0 0 12 12",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            circle {
                cx: "6",
                cy: "6",
                r: "5",
                fill: "#FFE0E0",
                stroke: "#D13438",
                stroke_width: "1",
            }
            path {
                d: "M4 4L8 8M8 4L4 8",
                stroke: "#D13438",
                stroke_width: "1.2",
                stroke_linecap: "round",
            }
        }
    }
}

/// Encrypted (EFS) indicator
pub fn encrypted_badge() -> Element {
    rsx! {
        svg {
            width: "12",
            height: "12",
            view_box: "0 0 12 12",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            rect {
                x: "2.5",
                y: "5",
                width: "7",
                height: "5.5",
                rx: "1",
                fill: "#DFF6FF",
                stroke: "#0078D4",
                stroke_width: "1",
            }
            path {
                d: "M4 5V3.5C4 2.39543 4.89543 1.5 6 1.5C7.10457 1.5 8 2.39543 8 3.5V5",
                stroke: "#0078D4",
                stroke_width: "1",
                fill: "none",
            }
        }
    }
}

/// NTFS Explorer app icon
pub fn app_icon() -> Element {
    rsx! {
        svg {
            width: "24",
            height: "24",
            view_box: "0 0 24 24",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            // Hard drive with magnifying glass
            rect {
                x: "2",
                y: "6",
                width: "16",
                height: "12",
                rx: "2",
                fill: "#0078D4",
            }
            // Drive face
            rect {
                x: "3",
                y: "7",
                width: "14",
                height: "10",
                rx: "1",
                fill: "#FFFFFF",
            }
            // LED
            circle {
                cx: "5",
                cy: "15",
                r: "1",
                fill: "#00CC6A",
            }
            // Magnifying glass
            circle {
                cx: "17",
                cy: "10",
                r: "5",
                fill: "#50E6FF",
                stroke: "#0078D4",
                stroke_width: "2",
            }
            path {
                d: "M20 13L23 16",
                stroke: "#0078D4",
                stroke_width: "2.5",
                stroke_linecap: "round",
            }
        }
    }
}

/// Empty state folder icon (large)
pub fn empty_folder_large() -> Element {
    rsx! {
        svg {
            width: "64",
            height: "64",
            view_box: "0 0 64 64",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M8 16C8 12.6863 10.6863 10 14 10H24.6863C26.0125 10 27.2845 10.5268 28.2222 11.4645L32 15.2426H50C53.3137 15.2426 56 17.929 56 21.2426V48C56 51.3137 53.3137 54 50 54H14C10.6863 54 8 51.3137 8 48V16Z",
                fill: "#DCBA6A",
            }
            path {
                d: "M8 24C8 21.7909 9.79086 20 12 20H52C54.2091 20 56 21.7909 56 24V48C56 51.3137 53.3137 54 50 54H14C10.6863 54 8 51.3137 8 48V24Z",
                fill: "#F2D675",
            }
        }
    }
}
