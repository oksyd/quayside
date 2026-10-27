use crate::{Error, Result, error::Code};
use rustix::{
    fs::{Mode, OFlags},
    termios::{self, LocalModes, OptionalActions, SpecialCodeIndex, Termios},
};
use std::{
    fs::File,
    io::{self, IsTerminal, Read, Write},
    os::fd::AsFd,
};
use tokio::io::unix::AsyncFd;
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSWORD: usize = 65_536;

pub(crate) async fn read(from_stdin: bool) -> Result<Zeroizing<String>> {
    let secret = if from_stdin {
        tokio::task::spawn_blocking(|| {
            let mut secret = Zeroizing::new(String::new());
            io::stdin()
                .take(MAX_PASSWORD as u64 + 1)
                .read_to_string(&mut secret)?;
            if secret.len() > MAX_PASSWORD {
                return Err(Error::input("password input exceeds 64KiB"));
            }
            if secret.ends_with('\n') {
                secret.pop();
                if secret.ends_with('\r') {
                    secret.pop();
                }
            }
            Ok(secret)
        })
        .await
        .map_err(|_| Error::new(Code::Execution, "password input task failed"))??
    } else {
        if !io::stdin().is_terminal() {
            return Err(Error::input(
                "non-interactive login requires --password-stdin",
            ));
        }
        let tty = rustix::fs::open(
            "/dev/tty",
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        prompt(File::from(tty)).await?
    };
    if secret.is_empty() {
        return Err(Error::input("empty password/token"));
    }
    Ok(secret)
}

// The future owns terminal settings: cancellation restores them before the CLI exits.
// A blocking password reader cannot provide that guarantee when its task is abandoned.
struct Terminal {
    file: File,
    original: Termios,
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(&self.file, OptionalActions::Flush, &self.original);
        let _ = writeln!(&self.file);
    }
}

async fn prompt(file: File) -> Result<Zeroizing<String>> {
    let original = termios::tcgetattr(&file).map_err(io::Error::from)?;
    let mut hidden = original.clone();
    hidden
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
    hidden.special_codes[SpecialCodeIndex::VMIN] = 1;
    hidden.special_codes[SpecialCodeIndex::VTIME] = 0;
    let terminal = Terminal { file, original };
    termios::tcsetattr(&terminal.file, OptionalActions::Flush, &hidden).map_err(io::Error::from)?;
    // SAFETY: The borrowed descriptor stays open and unchanged until input is dropped.
    // The terminal owns it and outlives this registration, including on cancellation.
    let input = unsafe { AsyncFd::register(terminal.file.as_fd()) }.map_err(io::Error::from)?;
    write!(&terminal.file, "Password / token: ")?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 256]);
    let mut escape = 0;
    loop {
        let count = match input
            .readable()
            .await?
            .try_io(|fd| rustix::io::read(fd.get_ref(), &mut *buffer).map_err(io::Error::from))
        {
            Ok(result) => result?,
            Err(_) => continue,
        };
        if count == 0 {
            return Err(Error::input("password input ended before Enter"));
        }
        for &byte in &buffer[..count] {
            match byte {
                3 => return Err(Error::new(Code::Interrupted, "interrupted by user")),
                b'\n' | b'\r' => {
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| Error::input("password input is not valid UTF-8"))?;
                    return Ok(Zeroizing::new(text.to_owned()));
                }
                _ if escape != 0 => {
                    escape = if (escape == 1 && matches!(byte, b'[' | b'O'))
                        || (escape == 2 && !(0x40..=0x7e).contains(&byte))
                    {
                        2
                    } else {
                        0
                    };
                }
                27 => escape = 1,
                8 | 127 => erase_character(&mut bytes),
                21 => bytes.zeroize(),
                23 => {
                    while bytes.last() == Some(&b' ') {
                        erase_character(&mut bytes);
                    }
                    while bytes.last().is_some_and(|b| *b != b' ') {
                        erase_character(&mut bytes);
                    }
                }
                4 if bytes.is_empty() => return Err(Error::input("empty password/token")),
                0..=31 => {}
                _ => {
                    if bytes.len() == MAX_PASSWORD {
                        return Err(Error::input("password input exceeds 64KiB"));
                    }
                    bytes.push(byte);
                }
            }
        }
        buffer.zeroize();
    }
}

fn erase_character(bytes: &mut Vec<u8>) {
    while let Some(last) = bytes.last_mut() {
        let continuation = *last & 0xc0 == 0x80;
        *last = 0;
        bytes.pop();
        if !continuation {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::pty::{self, OpenptFlags};
    use std::time::Duration;

    fn terminal_pair() -> (AsyncFd<File>, File) {
        let master = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        pty::grantpt(&master).unwrap();
        pty::unlockpt(&master).unwrap();
        let path = pty::ptsname(&master, Vec::new()).unwrap();
        let slave = rustix::fs::open(
            &path,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let flags = rustix::fs::fcntl_getfl(&master).unwrap();
        rustix::fs::fcntl_setfl(&master, flags | OFlags::NONBLOCK).unwrap();
        // SAFETY: AsyncFd owns the file, which is never closed or replaced while registered.
        let master = unsafe { AsyncFd::register(File::from(master)) }.unwrap();
        (master, File::from(slave))
    }

    async fn wait_for_prompt(master: &AsyncFd<File>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut output = Vec::new();
            while !output.ends_with(b"Password / token: ") {
                let mut buffer = [0u8; 128];
                match master
                    .readable()
                    .await
                    .unwrap()
                    .try_io(|fd| fd.get_ref().read(&mut buffer))
                {
                    Ok(result) => output.extend_from_slice(&buffer[..result.unwrap()]),
                    Err(_) => continue,
                }
            }
        })
        .await
        .expect("password prompt did not appear");
    }

    #[tokio::test]
    async fn cancelling_password_input_restores_terminal_settings() {
        let (master, slave) = terminal_pair();
        let original = termios::tcgetattr(&slave).unwrap();
        let inspect = slave.try_clone().unwrap();
        let mut password = Box::pin(prompt(slave));
        tokio::select! {
            result = &mut password => panic!("input unexpectedly finished: {}", result.is_ok()),
            () = wait_for_prompt(&master) => {}
        }
        assert!(
            !termios::tcgetattr(&inspect)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        );
        drop(password);
        let restored = termios::tcgetattr(&inspect).unwrap();
        assert_eq!(restored.local_modes, original.local_modes);
        for code in [SpecialCodeIndex::VMIN, SpecialCodeIndex::VTIME] {
            assert_eq!(restored.special_codes[code], original.special_codes[code]);
        }
    }

    #[tokio::test]
    async fn password_entry_handles_editing_and_interruption_without_echo() {
        for (input, expected) in [
            ("wrong\u{15}secreté\u{7f}\u{1b}[D\n", Some("secret")),
            ("secret wrong\u{17}\u{7f}\n", Some("secret")),
            ("partial\u{3}", None),
        ] {
            let (master, slave) = terminal_pair();
            let inspect = slave.try_clone().unwrap();
            let original = termios::tcgetattr(&inspect).unwrap();
            let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(prompt(slave), async {
                    wait_for_prompt(&master).await;
                    master.get_ref().write_all(input.as_bytes()).unwrap();
                })
            })
            .await
            .expect("password input did not finish");
            if let Some(expected) = expected {
                assert_eq!(result.unwrap().as_str(), expected);
            } else {
                assert_eq!(result.unwrap_err().code, Code::Interrupted);
            }
            assert_eq!(
                termios::tcgetattr(&inspect).unwrap().local_modes,
                original.local_modes
            );
            let mut output = [0u8; 128];
            let count = master.get_ref().read(&mut output).unwrap();
            assert!(output[..count].iter().all(|b| matches!(b, b'\r' | b'\n')));
        }
    }
}
