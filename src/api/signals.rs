use std::convert::{Infallible, TryFrom};

use nix::sys::signal::Signal;
use tokio::sync::mpsc;
use warp::http::StatusCode;

use super::{ApiReply, ErrorMessage};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct KillSignal {
    signal: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OkReply {
    ok: bool,
}

pub async fn send_kill_signal(
    mut tx_sig: mpsc::Sender<Signal>,
    kill_signal: KillSignal,
) -> Result<impl warp::Reply, Infallible> {
    {
        match Signal::try_from(kill_signal.signal) {
            Ok(sig) => {
                if let Err(e) = tx_sig.send(sig).await {
                    return Ok(ApiReply::Err(warp::reply::with_status(
                        warp::reply::json(&ErrorMessage {
                            message: format!("{}", e),
                        }),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    )));
                }
                Ok(ApiReply::Ok(warp::reply::json(&OkReply { ok: true })))
            }
            Err(e) => {
                error!("Received unknown signal {}", kill_signal.signal);
                Ok(ApiReply::Err(warp::reply::with_status(
                    warp::reply::json(&ErrorMessage {
                        message: format!("{}", e),
                    }),
                    StatusCode::BAD_REQUEST,
                )))
            }
        }
    }
}
