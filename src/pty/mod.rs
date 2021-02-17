use std::fs::File as StdFile;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::fs::File as TokioFile;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;

/*
 * PtyMaster
 */
pub struct PtyMaster {
    file: StdFile,
}

impl PtyMaster {
    pub fn open() -> Result<Self, io::Error> {
        use std::os::unix::io::FromRawFd as _;

        let file = unsafe {
            let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);

            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::grantpt(fd) != 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::unlockpt(fd) != 0 {
                return Err(io::Error::last_os_error());
            }

            StdFile::from_raw_fd(fd)
        };

        Ok(Self { file })
    }

    pub fn open_slave(&self) -> Result<StdFile, io::Error> {
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _};

        let file = unsafe {
            let mut buf: [libc::c_char; 512] = [0; 512];

            #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
            {
                if libc::ptsname_r(self.file.as_raw_fd(), buf.as_mut_ptr(), buf.len()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            {
                let st = libc::ptsname(self.file.as_raw_fd());
                if st.is_null() {
                    return Err(io::Error::last_os_error());
                }
                libc::strncpy(buf.as_mut_ptr(), st, buf.len());
            }

            let fd = libc::open(buf.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);

            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            StdFile::from_raw_fd(fd)
        };

        Ok(file)
    }

    pub fn split(self) -> Result<(PtyMasterRead, PtyMasterWrite), io::Error> {
        Ok((
            PtyMasterRead {
                file: TokioFile::from_std(self.file.try_clone()?),
            },
            PtyMasterWrite {
                file: TokioFile::from_std(self.file),
            },
        ))
    }
}

/*
 * PtyMasterRead
 */
pub struct PtyMasterRead {
    file: TokioFile,
}

impl PtyMasterRead {
    fn get_file(self: Pin<&mut Self>) -> Pin<&mut TokioFile> {
        unsafe { self.map_unchecked_mut(|s| &mut s.file) }
    }
}

impl AsyncRead for PtyMasterRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_file().poll_read(cx, buf)
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/*
 * PtyMasterWrite
 */
pub struct PtyMasterWrite {
    file: TokioFile,
}

impl PtyMasterWrite {
    fn get_file(self: Pin<&mut Self>) -> Pin<&mut TokioFile> {
        unsafe { self.map_unchecked_mut(|s| &mut s.file) }
    }

    pub fn resize(&self, cols: libc::c_ushort, rows: libc::c_ushort) -> Result<(), io::Error> {
        let winsz = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        if unsafe { libc::ioctl(self.file.as_raw_fd(), libc::TIOCSWINSZ.into(), &winsz) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

impl AsyncWrite for PtyMasterWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_file().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.get_file().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.get_file().poll_shutdown(cx)
    }
}

pub trait PtyCommandExt {
    fn spawn_pty(
        &mut self,
        pty_master: &PtyMaster,
        raw: bool,
    ) -> Result<tokio::process::Child, io::Error>;
}

impl PtyCommandExt for Command {
    fn spawn_pty(
        &mut self,
        pty_master: &PtyMaster,
        raw: bool,
    ) -> Result<tokio::process::Child, io::Error> {
        let master_fd = pty_master.as_raw_fd();
        let slave = pty_master.open_slave()?;
        let slave_fd = slave.as_raw_fd();

        self.stdin(slave.try_clone()?);
        self.stdout(slave.try_clone()?);
        self.stderr(slave.try_clone()?);

        debug!("set stdin, stdout and stderr");

        unsafe {
            self.pre_exec(move || {
                if raw {
                    let mut attrs: libc::termios = std::mem::zeroed();

                    if libc::tcgetattr(slave_fd, &mut attrs as _) != 0 {
                        return Err(io::Error::last_os_error());
                    }

                    libc::cfmakeraw(&mut attrs as _);

                    if libc::tcsetattr(slave_fd, libc::TCSANOW, &attrs as _) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }

                // This is OK even though we don't own master since this process is
                // about to become something totally different anyway.
                if libc::close(master_fd) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::ioctl(0, libc::TIOCSCTTY.into(), 1) != 0 {
                    return Err(io::Error::last_os_error());
                }

                Ok(())
            });
        }

        self.spawn()
    }
}
