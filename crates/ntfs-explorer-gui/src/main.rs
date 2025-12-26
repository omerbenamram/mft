mod app;
mod components;
mod icons;
#[cfg(feature = "desktop")]
mod menus;
mod mft_only;
mod settings;
mod styles;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    #[cfg(feature = "desktop")]
    {
        use dioxus::LaunchBuilder;
        use dioxus::desktop::{Config, WindowBuilder};

        LaunchBuilder::desktop()
            .with_cfg(
                Config::new().with_menu(menus::build_menu()).with_window(
                    WindowBuilder::new()
                        .with_title("NTFS Explorer")
                        .with_inner_size(dioxus::desktop::LogicalSize::new(1200.0, 800.0)),
                ),
            )
            .launch(app::app);
    }

    // LiveView runs the app natively, but renders the UI in the browser.
    #[cfg(feature = "liveview")]
    {
        dioxus::launch(app::app);
    }

    #[cfg(feature = "web")]
    {
        dioxus::launch(app::app);
    }
}
