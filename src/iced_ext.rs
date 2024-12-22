use std::ops::{Deref, DerefMut};

use iced_x86::{IcedError, Instruction};

/// Wrapper around [`iced_x86::Decoder`] which exposes the underlying data buffer as a raw pointer.
pub struct Decoder<'a> {
    data: *const [u8],
    inner: iced_x86::Decoder<'a>,
}

unsafe impl Send for Decoder<'_> {}
unsafe impl Sync for Decoder<'_> {}

impl<'a> Decoder<'a> {
    #[inline]
    pub fn new(bitness: u32, data: &'a [u8], options: u32) -> Decoder<'a> {
        Self::try_new(bitness, data, options).unwrap()
    }

    #[inline]
    pub fn with_ip(bitness: u32, data: &'a [u8], ip: u64, options: u32) -> Decoder<'a> {
        Self::try_with_ip(bitness, data, ip, options).unwrap()
    }

    #[inline]
    pub fn try_new(bitness: u32, data: &'a [u8], options: u32) -> Result<Decoder<'a>, IcedError> {
        Self::try_with_ip(bitness, data, 0, options)
    }

    #[inline]
    pub fn try_with_ip(
        bitness: u32,
        data: &'a [u8],
        ip: u64,
        options: u32,
    ) -> Result<Self, IcedError> {
        Ok(Self {
            data,
            inner: iced_x86::Decoder::try_with_ip(bitness, data, ip, options)?,
        })
    }

    #[inline]
    pub unsafe fn try_with_slice_ptr(
        bitness: u32,
        data: *const [u8],
        ip: u64,
        options: u32,
    ) -> Result<Self, IcedError> {
        Ok(Self {
            data,
            inner: unsafe { iced_x86::Decoder::try_with_slice_ptr(bitness, data, ip, options)? },
        })
    }

    /// Get a raw pointer to the data buffer this decoder operates on.
    #[inline]
    pub fn data_ptr(&self) -> *const [u8] {
        self.data
    }

    /// Tries to set both the IP and position of the decoder, deducing the position from the IP
    /// value.
    ///
    /// Fails without setting the IP if the resulting position would be outside of the decoder's
    /// buffer range.
    pub fn set_pos_from_ip(&mut self, ip: u64) -> Result<(), IcedError> {
        // Compute the change in IP and apply the same change to position
        let offset = ip.wrapping_sub(self.ip());
        let new_pos = self.position().wrapping_add(offset as usize);
        self.set_position(new_pos)?;
        self.set_ip(ip);
        Ok(())
    }

    /// Decodes the instruction in place at the given IP, setting the decoder's position to match it
    /// first.
    pub fn decode_out_at(
        &mut self,
        ip: u64,
        instruction: &mut Instruction,
    ) -> Result<(), IcedError> {
        self.set_pos_from_ip(ip)?;
        Ok(self.decode_out(instruction))
    }

    /// Decodes the instruction at the given IP, setting the decoder's position to match it first.
    pub fn decode_at(&mut self, ip: u64) -> Result<Instruction, IcedError> {
        self.set_pos_from_ip(ip)?;
        Ok(self.decode())
    }
}

impl<'a> Deref for Decoder<'a> {
    type Target = iced_x86::Decoder<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> DerefMut for Decoder<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
