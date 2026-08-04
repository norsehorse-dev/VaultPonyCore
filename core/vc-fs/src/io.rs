//! Bridge from our `BlockDevice` to `std::io` traits, for adapters built on
//! crates that expect Read/Write/Seek (`fatfs`, `ntfs`).

use std::io::{Read, Seek, SeekFrom, Write};
use vc_io::BlockDevice;

pub struct DeviceIo {
    dev: Box<dyn BlockDevice>,
    pos: u64,
    len: u64,
}

impl DeviceIo {
    pub fn new(mut dev: Box<dyn BlockDevice>) -> vc_types::VcResult<Self> {
        let len = dev.len()?;
        Ok(Self { dev, pos: 0, len })
    }
}

fn to_io(e: vc_types::VcError) -> std::io::Error {
    match e {
        vc_types::VcError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}

impl Read for DeviceIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(remaining) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.dev.read_at(self.pos, &mut buf[..n]).map_err(to_io)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for DeviceIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.write_at(self.pos, buf).map_err(to_io)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.dev.flush().map_err(to_io)
    }
}

impl Seek for DeviceIo {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match new {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek out of range",
            )),
        }
    }
}
