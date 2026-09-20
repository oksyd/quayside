#![allow(dead_code)]
use quayside::{
    config::{Config, RegistryConfig},
    digest::Digest,
    model::{Descriptor, OCI_INDEX, OCI_MANIFEST},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

// Match dirs' platform defaults without changing the test process environment.
pub fn config_home(root: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        root.join("Library/Application Support")
    } else {
        root.join("xdg")
    }
}

pub fn data_home(root: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        root.join("Library/Application Support")
    } else {
        root.join("data")
    }
}

pub struct Harness {
    pub root: tempfile::TempDir,
    pub config: Config,
}
impl Harness {
    pub fn new(hosts: &[(&str, bool)]) -> Self {
        let mut config = Config::default();
        config.transfer.max_retries = 0;
        config.transfer.connect_timeout = "2s".into();
        config.transfer.metadata_timeout = "5s".into();
        config.transfer.idle_timeout = "2s".into();
        config.transfer.chunk_size = "64KiB".into();
        for (host, plain_http) in hosts {
            config.registries.insert(
                (*host).into(),
                RegistryConfig {
                    plain_http: *plain_http,
                    ..Default::default()
                },
            );
        }
        let root = tempfile::tempdir().unwrap();
        quayside::storage::restrict(root.path(), true).unwrap();
        fs::create_dir(root.path().join("tmp")).unwrap();
        fs::create_dir_all(config_home(root.path()).join("docker")).unwrap();
        fs::write(config_home(root.path()).join("docker/daemon.json"), b"{}").unwrap();
        Self { root, config }
    }
    pub fn daemon_config(&self) -> PathBuf {
        config_home(self.root.path()).join("docker/daemon.json")
    }
    pub fn command(&self, args: &[&str]) -> Command {
        let config = self.root.path().join("config.toml");
        fs::write(&config, toml::to_string(&self.config).unwrap()).unwrap();
        let binary = std::env::var_os("QUAYSIDE_TEST_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_quayside").into());
        let mut command = Command::new(binary);
        command
            .args(["--config"])
            .arg(config)
            .arg("--authfile")
            .arg(self.root.path().join("auth.json"))
            .arg("--keyfile")
            .arg(self.root.path().join("keys/master.key"));
        command.env("HOME", self.root.path());
        command.env("XDG_DATA_HOME", data_home(self.root.path()));
        command.env("TMPDIR", self.root.path().join("tmp"));
        command.env("XDG_CONFIG_HOME", self.root.path().join("xdg"));
        for name in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
            "no_proxy",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            command.env_remove(name);
        }
        command.args(args);
        command
    }
    pub fn output(&self, args: &[&str], exit: i32) -> Output {
        let out = self.command(args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(exit),
            "{args:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
    pub fn json(&self, args: &[&str], exit: i32) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        serde_json::from_slice(&self.output(&args, exit).stdout).unwrap()
    }
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub delay: Duration,
}
impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: vec![],
            delay: Duration::ZERO,
        }
    }
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }
}
fn serve<S: Read + Write>(
    mut stream: S,
    handler: &dyn Fn(Request) -> Response,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.len() > 65536 {
            return Ok(());
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap().to_owned();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if length > 64 * 1024 * 1024 {
        return Ok(());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let response = handler(Request {
        method: method.clone(),
        path,
        headers,
        body,
    });
    write!(
        stream,
        "HTTP/1.1 {} Test\r\nConnection: close\r\n",
        response.status
    )?;
    if !response
        .headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("content-length"))
    {
        write!(stream, "Content-Length: {}\r\n", response.body.len())?;
    }
    for (k, v) in response.headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.flush()?;
    thread::sleep(response.delay);
    if method != "HEAD" {
        stream.write_all(&response.body)?;
    }
    stream.flush()
}
pub fn configure_connection(stream: &TcpStream) -> std::io::Result<()> {
    // macOS/BSD accept() can inherit the listener's nonblocking mode.
    // The HTTP parser and rustls stream below use blocking I/O.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))
}

pub struct Server {
    pub host: String,
    pub connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub fn new(handler: impl Fn(Request) -> Response + Send + Sync + 'static) -> Self {
        Self::start(None, handler)
    }
    pub fn start(
        tls: Option<Arc<rustls::ServerConfig>>,
        handler: impl Fn(Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = listener.local_addr().unwrap().to_string();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        let handler = Arc::new(handler);
        let worker = thread::spawn(move || {
            let mut workers = vec![];
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        count.fetch_add(1, Ordering::SeqCst);
                        configure_connection(&stream).unwrap();
                        let handler = handler.clone();
                        let tls = tls.clone();
                        workers.push(thread::spawn(move || {
                            let result = if let Some(config) = tls {
                                let connection = rustls::ServerConnection::new(config).unwrap();
                                serve(
                                    rustls::StreamOwned::new(connection, stream),
                                    handler.as_ref(),
                                )
                            } else {
                                serve(stream, handler.as_ref())
                            };
                            if let Err(error) = result {
                                eprintln!("test server request failed: {:?}", error.kind());
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("test listener: {e}"),
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            host,
            connections,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

pub struct Image {
    pub manifest: Vec<u8>,
    pub digest: String,
    pub blobs: BTreeMap<String, Vec<u8>>,
    pub directory: PathBuf,
}
pub fn image_layout(root: &Path, layers: usize, layer_size: usize) -> Image {
    image_layout_for(root, layers, layer_size, "arm64")
}

pub fn image_layout_for(
    root: &Path,
    layers: usize,
    layer_size: usize,
    architecture: &str,
) -> Image {
    let config = serde_json::to_vec(&json!({"architecture":architecture,"os":"linux","variant":if architecture == "arm64" {Some("v8")} else {None},"config":{"Labels":{"fixture":"quayside"}},"rootfs":{"type":"layers","diff_ids":[]}})).unwrap();
    let config_desc = Descriptor::new(
        "application/vnd.oci.image.config.v1+json",
        Digest::sha256(&config),
        config.len() as u64,
    );
    let mut blobs = BTreeMap::from([(config_desc.digest.to_string(), config)]);
    let mut descriptors = vec![];
    for i in 0..layers {
        let body = vec![(i + 1) as u8; layer_size];
        let d = Descriptor::new(
            "application/vnd.oci.image.layer.v1.tar",
            Digest::sha256(&body),
            body.len() as u64,
        );
        blobs.insert(d.digest.to_string(), body);
        descriptors.push(d);
    }
    let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,"config":config_desc,"layers":descriptors})).unwrap();
    write_layout(root, manifest, blobs)
}

pub fn artifact_layout(root: &Path, java: bool, opaque: bool) -> Image {
    let config = if opaque {
        b"opaque config".to_vec()
    } else {
        b"{}".to_vec()
    };
    let layer = b"synthetic database payload".to_vec();
    let config_desc = Descriptor::new(
        "application/vnd.aquasec.trivy.config.v1+json",
        Digest::sha256(&config),
        config.len() as u64,
    );
    let layer_desc = Descriptor::new(
        if java {
            "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
        } else {
            "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
        },
        Digest::sha256(&layer),
        layer.len() as u64,
    );
    let blobs = BTreeMap::from([
        (config_desc.digest.to_string(), config),
        (layer_desc.digest.to_string(), layer),
    ]);
    let mut value = json!({
        "schemaVersion":2,"mediaType":OCI_MANIFEST,
        "config":config_desc,"layers":[layer_desc],
        "annotations":{"org.opencontainers.image.title":"db.tar.gz"},
        "future":{"preserve":true}
    });
    if !java && !opaque {
        value["artifactType"] = json!("application/vnd.aquasec.trivy.config.v1+json");
        value["config"]["mediaType"] = json!("application/vnd.oci.empty.v1+json");
        value["config"]["data"] = json!("e30=");
    }
    write_layout(root, serde_json::to_vec(&value).unwrap(), blobs)
}

fn write_layout(root: &Path, manifest: Vec<u8>, blobs: BTreeMap<String, Vec<u8>>) -> Image {
    let digest = Digest::sha256(&manifest);
    let directory = root.join("layout");
    fs::create_dir_all(directory.join("blobs/sha256")).unwrap();
    for (digest, body) in &blobs {
        fs::write(
            directory
                .join("blobs/sha256")
                .join(digest.split_once(':').unwrap().1),
            body,
        )
        .unwrap();
    }
    fs::write(
        directory.join("blobs/sha256").join(digest.encoded()),
        &manifest,
    )
    .unwrap();
    fs::write(
        directory.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(directory.join("index.json"),serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[Descriptor::new(OCI_MANIFEST,digest.clone(),manifest.len() as u64)]})).unwrap()).unwrap();
    Image {
        manifest,
        digest: digest.to_string(),
        blobs,
        directory,
    }
}
