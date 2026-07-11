use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, RunEvent, WindowEvent,
};

mod sidecar;
use sidecar::SidecarState;

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn main() {
    let app = tauri::Builder::default()
        .setup(|app| {
            app.manage(SidecarState(std::sync::Mutex::new(None)));

            let tray_result = (|| -> tauri::Result<()> {
                let show = MenuItem::with_id(app, "show", "打开 Forge Agent", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show, &quit])?;

                let mut tray = TrayIconBuilder::new()
                    .tooltip("Forge Agent")
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => show_main_window(app),
                        "quit" => app.exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main_window(&tray.app_handle());
                        }
                    });

                if let Some(icon) = app.default_window_icon() {
                    tray = tray.icon(icon.clone());
                }
                tray.build(app)?;
                Ok(())
            })();
            if let Err(error) = tray_result {
                eprintln!("Forge Agent tray initialization failed: {error}");
            }

            match sidecar::launch(app.handle()) {
                Ok(child) => {
                    let state = app.state::<SidecarState>();
                    if let Ok(mut state) = state.0.lock() {
                        *state = Some(child);
                    }
                }
                Err(error) => eprintln!("Forge Agent sidecar launch failed: {error}"),
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build Forge Agent");
    app.run(|handle, event| {
        if let RunEvent::ExitRequested { .. } = event {
            sidecar::stop(&handle.state::<SidecarState>());
        }
    });
}
