use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;

use futures::channel::oneshot;
use futures::{Future, FutureExt, TryStream};
use nix::sys::signal::Signal;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use warp::Filter;

pub mod exec;
#[macro_use]
pub mod macros;
pub mod signals;
pub mod sys;

pub enum ApiReply<A, B> {
    Ok(A),
    Err(B),
}

impl<A, B> warp::Reply for ApiReply<A, B>
where
    A: warp::Reply,
    B: warp::Reply,
{
    fn into_response(self) -> warp::reply::Response {
        let mut res = match self {
            ApiReply::Ok(a) => a.into_response(),
            ApiReply::Err(b) => b.into_response(),
        };
        let headers = res.headers_mut();
        headers.insert(
            "fly-init-version",
            warp::http::header::HeaderValue::from_str(env!("VERGEN_SHA_SHORT")).unwrap(),
        );
        res
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorMessage {
    message: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExitCode {
    pub code: i32,
    pub oom_killed: bool,
}

pub fn server<I>(
    envs: HashMap<String, String>,
    waitpid_mutex: Arc<Mutex<()>>,
    incoming: I,
) -> (
    impl Future<Output = ()>,
    oneshot::Sender<(i32, bool)>,
    mpsc::Receiver<Signal>,
)
where
    I: TryStream + Send + 'static,
    I::Ok: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    I::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let v1 = warp::path("v1");

    let status_show = v1.and(warp::path("status"));
    let get_status = warp::get().and(status_show).map(status);

    let sysinfo_index = v1.and(warp::path("sysinfo"));

    let get_sysinfo = warp::get().and(sysinfo_index).map(sys::list_sysinfo);

    let kill_signal_path = v1.and(warp::path("signals"));

    let json_body = warp::body::content_length_limit(1024 * 16).and(warp::body::json());

    let (tx_sig, rx_sig) = mpsc::channel(1);

    let post_signals = warp::post()
        .and(kill_signal_path)
        .and(warp::any().map(move || tx_sig.clone()))
        .and(json_body)
        .and_then(signals::send_kill_signal);

    let (tx, rx) = oneshot::channel::<(i32, bool)>();

    let rx = rx.shared();

    let get_exit_code = warp::get()
        .and(v1.and(warp::path("exit_code")))
        .and(warp::any().map(move || rx.clone()))
        .and_then(
            |rx: futures::future::Shared<oneshot::Receiver<(i32, bool)>>| async move {
                debug!("Received request for exit code");
                match rx.await {
                    Ok((code, oom_killed)) => Ok(warp::reply::json(&ExitCode { code, oom_killed })),
                    Err(_e) => Err(warp::reject::not_found()),
                }
            },
        );

    let env_filter = warp::any().map(move || envs.clone());

    let post_exec = warp::post()
        .and(v1.and(warp::path("exec")))
        .and(warp::body::content_length_limit(1024 * 16).and(warp::body::json()))
        .and(env_filter.clone())
        .and(warp::any().map(move || waitpid_mutex.clone()))
        .and_then(exec::exec_cmd);

    let ws_exec = v1
        .and(warp::path("ws"))
        .and(warp::path("exec"))
        .and(warp::ws())
        .and(env_filter.clone())
        .map(exec::exec_ws);

    (
        warp::serve(combine!(
            get_status,
            get_exit_code,
            post_signals,
            get_sysinfo,
            post_exec,
            ws_exec,
        ))
        .serve_incoming(incoming),
        tx,
        rx_sig,
    )
}

pub fn status() -> impl warp::Reply {
    warp::reply::json(&serde_json::json!({"ok": true}))
}
