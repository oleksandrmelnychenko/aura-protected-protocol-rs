const WINDOW_SIZE: u64 = 128;
const BITMAP_WORDS: usize = 128 / 64;

pub struct ReplayWindow {
    high_water: u64,
    bitmap: [u64; BITMAP_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            high_water: 0,
            bitmap: [0; BITMAP_WORDS],
        }
    }

    pub const fn window_size() -> u64 {
        WINDOW_SIZE
    }

    pub const fn high_water_mark(&self) -> u64 {
        self.high_water
    }

    pub const fn bitmap_words(&self) -> [u64; BITMAP_WORDS] {
        self.bitmap
    }

    pub const fn from_parts(high_water: u64, bitmap: [u64; BITMAP_WORDS]) -> Self {
        Self { high_water, bitmap }
    }

    pub const fn check(&self, counter: u64) -> bool {
        if counter > self.high_water {
            return true;
        }
        let delta = self.high_water - counter;
        if delta >= WINDOW_SIZE {
            return false;
        }
        #[allow(clippy::cast_possible_truncation)]
        let idx = delta as usize;
        let word = idx / 64;
        let bit = idx % 64;
        (self.bitmap[word] & (1u64 << bit)) == 0
    }

    pub fn mark(&mut self, counter: u64) {
        if counter > self.high_water {
            let shift = counter - self.high_water;
            self.shift_window(shift);
            self.high_water = counter;
            self.bitmap[0] |= 1;
        } else {
            let delta = self.high_water - counter;
            if delta < WINDOW_SIZE {
                #[allow(clippy::cast_possible_truncation)]
                let idx = delta as usize;
                let word = idx / 64;
                let bit = idx % 64;
                self.bitmap[word] |= 1u64 << bit;
            }
        }
    }

    fn shift_window(&mut self, shift: u64) {
        if shift >= WINDOW_SIZE {
            self.bitmap = [0; BITMAP_WORDS];
            return;
        }

        #[allow(clippy::cast_possible_truncation)]
        let shift_usize = shift as usize;
        let word_shift = shift_usize / 64;
        let bit_shift = shift_usize % 64;

        if word_shift > 0 {
            for i in (word_shift..BITMAP_WORDS).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for word in self.bitmap.iter_mut().take(word_shift) {
                *word = 0;
            }
        }

        if bit_shift > 0 {
            for i in (1..BITMAP_WORDS).rev() {
                self.bitmap[i] =
                    (self.bitmap[i] << bit_shift) | (self.bitmap[i - 1] >> (64 - bit_shift));
            }
            self.bitmap[0] <<= bit_shift;
        }
    }
}
