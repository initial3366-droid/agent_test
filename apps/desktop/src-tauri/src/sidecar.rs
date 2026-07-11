use serde::Deserialize;
use std::{
    env,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
};
#[cfg(unix)]
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use url::Url;

pub struct SidecarState(pub Mutex<Option<Child>>);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadyEvent {
    event: String,
    token_file: Option<PathBuf>,
}

fn web_url() -> Result<(Url, String), String> {
    let value = env::var("FORGE_WEB_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let mut url = Url::parse(&value).map_err(|_| "invalid FORGE_WEB_URL".to_string())?;
    if url.username() != "" || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err("FORGE_WEB_URL cannot contain credentials, query, or fragment".to_string());
    }
    let loopback = url.host_str().map(|host| matches!(host, "localhost" | "127.0.0.1" | "::1")).unwrap_or(false);
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err("FORGE_WEB_URL must use HTTPS unless it is loopback".to_string());
    }
    let origin = url.origin().ascii_serialization();
    let normalized_path = url.path().trim_end_matches('/').to_string();
    url.set_path(&normalized_path);
    Ok((url, origin))
}

fn bundled_candidates(app: &AppHandle) -> Vec<PathBuf> {
    let executable_name = if cfg!(windows) { "forge-agent.exe" } else { "forge-agent" };
    let mut candidates = Vec::new();
    if let Ok(current) = env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(executable_name));
        }
    }
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join("binaries").join(executable_name));
        candidates.push(resources.join(executable_name));
    }
    candidates
}

fn sidecar_command(app: &AppHandle) -> Result<Command, String> {
    if cfg!(debug_assertions) {
        if let Ok(script) = env::var("FORGE_AGENT_SCRIPT") {
            let script = fs::canonicalize(script).map_err(|_| "FORGE_AGENT_SCRIPT does not exist".to_string())?;
            let node = env::var("FORGE_NODE_EXECUTABLE").unwrap_or_else(|_| "node".to_string());
            let mut command = Command::new(node);
            command.arg(script);
            return Ok(command);
        }
        if let Ok(executable) = env::var("FORGE_AGENT_EXECUTABLE") {
            let executable = fs::canonicalize(executable).map_err(|_| "FORGE_AGENT_EXECUTABLE does not exist".to_string())?;
            return Ok(Command::new(executable));
        }
    }
    let executable = bundled_candidates(app).into_iter().find(|candidate| candidate.is_file())
        .ok_or_else(|| "packaged forge-agent sidecar was not found".to_string())?;
    Ok(Command::new(executable))
}

fn valid_token(value: &str) -> bool {
    (32..=512).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn consume_token(path: &Path) -> Result<String, String> {
    let result = fs::read_to_string(path).map_err(|_| "could not read Agent token file".to_string());
    let _ = fs::remove_file(path);
    let token = result?.trim().to_string();
    if !valid_token(&token) {
        return Err("Agent returned an invalid bootstrap token".to_string());
    }
    Ok(token)
}

fn handle_stdout(stdout: impl std::io::Read + Send + 'static, mut web_url: Url) {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.len() > 16 * 1024 {
            return;
        }
        let ready: ReadyEvent = match serde_json::from_str::<ReadyEvent>(line.trim()) {
            Ok(value) if value.event == "forge-agent-ready" => value,
            _ => return,
        };
        let token = match ready.token_file {
            Some(path) => consume_token(&path),
            None => env::var("FORGE_AGENT_TOKEN").map_err(|_| "Agent did not provide a bootstrap token".to_string()),
        };
        if let Ok(token) = token {
            if valid_token(&token) {
                web_url.set_fragment(Some(&format!("forge_agent_token={token}")));
                let _ = open::that(web_url.as_str());
            }
        }
        line.clear();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            line.clear();
        }
    });
}

pub fn launch(app: &AppHandle) -> Result<Child, String> {
    let (url, origin) = web_url()?;
    let native_cache = app.path().app_cache_dir()
        .map_err(|_| "could not resolve the application cache directory".to_string())?
        .join("native-modules");
    fs::create_dir_all(&native_cache)
        .map_err(|_| "could not create the application cache directory".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&native_cache, fs::Permissions::from_mode(0o700))
            .map_err(|_| "could not secure the application cache directory".to_string())?;
    }
    let mut command = sidecar_command(app)?;
    command
        .env("WEB_ORIGIN", origin)
        .env("PKG_NATIVE_CACHE_PATH", native_cache)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command.spawn().map_err(|_| "failed to start forge-agent sidecar".to_string())?;
    let stdout = child.stdout.take().ok_or_else(|| "sidecar stdout was unavailable".to_string())?;
    handle_stdout(stdout, url);
    Ok(child)
}

#[cfg(unix)]
fn terminate_process_tree(process: &mut Child) {
    let process_group = process.id() as i32;
    unsafe {
        libc::killpg(process_group, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(process.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::killpg(process_group, libc::SIGKILL);
    }
    let _ = process.kill();
}

#[cfg(windows)]
fn terminate_process_tree(process: &mut Child) {
    let taskkill = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32").join("taskkill.exe"));
    if let Some(taskkill) = taskkill {
        let _ = Command::new(taskkill)
            .args(["/PID", &process.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = process.kill();
}

pub fn stop(state: &SidecarState) {
    if let Ok(mut child) = state.0.lock() {
        if let Some(mut process) = child.take() {
            terminate_process_tree(&mut process);
            let _ = process.wait();
        }
    }
}
