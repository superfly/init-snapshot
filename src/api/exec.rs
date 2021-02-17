use std::io;
use std::os::unix::{process::ExitStatusExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::collections::HashMap;
use std::sync::Arc;

use warp::reject::Rejection;
use futures::{SinkExt, StreamExt};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{ChildStdin, ChildStdout, Command};
use warp::filters::ws::Message;
use tokio::sync::Mutex;

use crate::pty::{PtyCommandExt, PtyMaster, PtyMasterRead, PtyMasterWrite};


#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    cmd: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExecResponse {
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub async fn exec_cmd(mut exec_req: ExecRequest, envs: HashMap<String, String>, waitpid_mutex: Arc<Mutex<()>>) -> Result<impl warp::Reply, Rejection> {
    let full_cmd = exec_req.cmd.join(" ");
    debug!("exec_cmd: {}", full_cmd);
    let mut command = Command::new(exec_req.cmd.swap_remove(0));
    for arg in exec_req.cmd.into_iter() {
        command.arg(arg);
    }

    command.envs(&envs);
    
    let guard = waitpid_mutex.lock().await;
    let output = command
        .output().await
        .map_err(|err| warp::reject::custom(ExecError::from(err)))?;

    drop(guard);

    let status = output.status;

    debug!("command '{}' exited with code: {}", full_cmd, status.code().map(|i| i.to_string()).unwrap_or_else(||"unknown".to_string()));

    Ok(warp::reply::json(&ExecResponse {
        exit_code: status.code(),
        exit_signal: status.signal(),
        stderr: output.stderr,
        stdout: output.stdout,
    }))
}

pub fn exec_ws(ws: warp::ws::Ws, envs: HashMap<String,String>) -> impl warp::Reply {
    ws.on_upgrade(|websocket| {
        async move {
            let (mut ws_write, mut ws_read) = websocket.split();
            debug!("exec ws upgrade, waiting for init client message");
            let (mut command, tty) = match ws_read.next().await {
                Some(Ok(client_msg)) => {
                    if client_msg.is_text() {
                        match serde_json::from_slice(client_msg.as_bytes()) {
                            Ok(client_msg) => match client_msg {
                                ClientMessage::Init {command, tty} => (command, tty),
                                _ => {
                                    error!("expecting init message, got something else");
                                    ws_write.send(Message::close()).await.ok();
                                    return;
                                }
                            },
                            Err(e) => {
                                error!("error decoding client message: {}", e);
                                return;
                            }
                        }
                    } else {
                        error!("expecting init message, got something else");
                        ws_write.send(Message::close()).await.ok();
                        return;
                    }
                },
                Some(Err(e)) => {
                    error!("error reading init message: {}", e);
                    return;
                }
                None => {
                    return;
                }
            };

            debug!("spawning process with command: {:?} (tty? {})", command, tty);

            if command.len() <= 0 {
                error!("command needs at least 1 item");
                ws_write.send(Message::close()).await.ok();
                return;
            }

            let mut cmd = Command::new(command.remove(0));
            for arg in command.into_iter(){
                cmd.arg(arg);
            }

            cmd.env_clear().envs(&envs);

            cmd.kill_on_drop(true);

            let (child_res, mut cmd_stdin, mut cmd_stdout) = if tty {
                let pty_master = PtyMaster::open().expect("could not create pty master");
                debug!("spawning with PTY");
                cmd.env("TERM", "xterm-256color");
                let res = cmd.spawn_pty(&pty_master, false);
                let (r,w) = pty_master.split().expect("could not split pty into read/write halves");
                (res, Stdin::Tty(w), Stdout::Tty(r))
            } else {
                debug!("spawning non-TTY");
                cmd.stdin(std::process::Stdio::null());
                cmd.stdout(std::process::Stdio::piped());
                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        error!("error spawning child process: {}", e);
                        ws_write.send(Message::close()).await.ok();
                        return;
                    }
                };
                let stdin = child.stdin.take().map(|s| Stdin::Normal(s)).unwrap_or(Stdin::DevNull);
                let stdout = child.stdout.take().map(|s| Stdout::Normal(s)).unwrap();
                (Ok(child), stdin, stdout)
            };

            let mut child = match child_res {
                Ok(c) => c,
                Err(e) => {
                    error!("error spawning child process: {}", e);
                    ws_write.send(Message::close()).await.ok();
                    return;
                }
            };

            let mut child_exited = false;
            let mut exit_loop_i = 10;

            loop {
                let mut buf = [0; 65536];
                let from_cmd = cmd_stdout.read(&mut buf);
                tokio::pin!(from_cmd);

                let from_ws = ws_read.next();
                tokio::pin!(from_ws);

                tokio::select! {
                    maybe_msg = &mut from_ws => match maybe_msg {
                        Some(Ok(msg)) => {
                            trace!("GOT A MESSAGE: {:?}", msg);
                            if msg.is_binary() {
                                match cmd_stdin.write_all(msg.as_bytes()).await {
                                    Ok(_) => trace!("wrote it to the cmd!"),
                                    Err(e) => debug!("error writing to cmd stdin: {}", e),
                                }
                            } else if msg.is_text() {
                                match serde_json::from_slice(msg.as_bytes()) {
                                    Ok(client_msg) => match client_msg {
                                        ClientMessage::Resize {cols, rows} => if tty {
                                            debug!("got resize message, cols: {}, rows: {}", cols, rows);
                                            if let Stdin::Tty(pty) = &mut cmd_stdin {
                                                match pty.resize(cols, rows) {
                                                    Ok(_) => debug!("resized pty correctly!"),
                                                    Err(e) => error!("error resizing pty: {}", e),
                                                }
                                            }
                                        },
                                        _ => {}
                                    },
                                    Err(e) => error!("error deserializing ws text message: {}", e)
                                }
                            } else if msg.is_close() {
                                debug!("closing exec ws, reason: {}", msg.to_str().unwrap_or("unknown"));
                                break;
                            }
                        },
                        Some(Err(e)) => {
                            error!("error reading from ws: {}", e);
                            break;
                        }
                        None => {
                            debug!("no more ws messages");
                            break;
                        }
                    },
                    read_res = &mut from_cmd => match read_res {
                        Ok(nread) => {
                            trace!("read {} bytes from the cmd stdout!", nread);
                            if nread == 0 {
                                debug!("end of stdout stream");
                                break;
                            }
                            match ws_write.send(Message::binary(&buf[..nread])).await {
                                Ok(_) => trace!("sent message to ws!"),
                                Err(e) => {
                                    error!("error writing to ws: {}", e);
                                    break;
                                }
                            }
                            if child_exited {
                                debug!("child had exited, breaking loop");
                                break;
                            }
                        },
                        Err(e) => {
                            error!("error reading from cmd stdout: {}", e);
                            break;
                        }
                    },
                    status = &mut child => {
                        if child_exited {
                            exit_loop_i -= 1;
                            if exit_loop_i <= 0 {
                                break;
                            }
                            continue;
                        }
                        child_exited = true;
                        let msg = match status {
                            Ok(es) => {
                                debug!("child exited {:?}", es);
                                ServerMessage::Exit{code: es.code(), signal: es.signal()}
                                
                            },
                            Err(e) => {
                                debug!("child exited w/ error {}", e);
                                ServerMessage::Error{message: e.to_string()}
                            }
                        };

                        match serde_json::to_string(&msg) {
                            Ok(s) => match ws_write.send(Message::text(s)).await {
                                Ok(_) => debug!("wrote exit code to websocket"),
                                Err(e) => debug!("error writing exit code to websocket: {}", e),
                            }
                            Err(e) => {
                                debug!("error encoding exit message: {}", e);
                            }
                        }

                        if let Err(e) = cmd_stdin.flush().await {
                            error!("error flushing cmd stdin: {}", e);
                        } else {
                            debug!("flushed stdin");
                        }
                        
                        if let Err(e) = cmd_stdin.shutdown().await {
                            error!("error shutting down cmd stdin: {}", e);
                        } else {
                            debug!("shutdown stdin");
                        }
                    }
                }
            }
            
            match ws_write.send(Message::close()).await {
                Ok(_) => debug!("successfully sent close message"),
                Err(e) => debug!("error sending exec close message: {}", e),
            }
            
        }
    })
}

#[derive(Debug)]
pub enum ExecError {
    Io(io::Error),
}

impl From<io::Error> for ExecError {
    fn from(e: io::Error) -> Self {
        ExecError::Io(e)
    }
}

impl warp::reject::Reject for ExecError {}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientMessage {
    Resize { cols: u16, rows: u16 },
    Init { command: Vec<String>, tty: bool },
}

#[derive(Serialize)]
enum ServerMessage {
    Exit {
        code: Option<i32>,
        signal: Option<i32>,
    },
    Error {
        message: String,
    },
}

#[pin_project(project = StdinProj)]
enum Stdin {
    DevNull,
    Normal(#[pin]ChildStdin),
    Tty(#[pin]PtyMasterWrite),
}

impl AsyncWrite for Stdin {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.project() {
            StdinProj::DevNull => Poll::Ready(Ok(buf.len())),
            StdinProj::Normal(stdin) => stdin.poll_write(cx, buf),
            StdinProj::Tty(stdin) => stdin.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        match self.project() {
            StdinProj::DevNull => Poll::Ready(Ok(())),
            StdinProj::Normal(stdin) => stdin.poll_flush(cx),
            StdinProj::Tty(stdin) => stdin.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        match self.project() {
            StdinProj::DevNull => Poll::Ready(Ok(())),
            StdinProj::Normal(stdin) => stdin.poll_shutdown(cx),
            StdinProj::Tty(stdin) => stdin.poll_shutdown(cx),
        }
    }
}


#[pin_project(project = StdoutProj)]
enum Stdout {
    Normal(#[pin]ChildStdout),
    Tty(#[pin]PtyMasterRead),
}

impl AsyncRead for Stdout {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.project() {
            StdoutProj::Normal(stdout) => stdout.poll_read(cx, buf),
            StdoutProj::Tty(stdout) => stdout.poll_read(cx, buf),
        }
    }
}