pub type VerInt = u16;

#[macro_export]
macro_rules! ver_int_len{
    () => {
        2
    };
}

#[macro_export]
macro_rules! versioned{
    ($et: ident $(, $dv: ident) *; $(($var: ident, $ver: literal, $t: ty)), *) => {
        #[derive($($dv), *)] 
        // hack to use default serialization for human readable
        pub enum $et {
            $($var($t),) *
        }
        impl $et {
            pub fn from_bytes(data: &[u8]) -> Result < $et,
            loga:: Error > {
                let version = $crate:: utils:: versioned:: VerInt:: from_le_bytes(
                    <[
                        u8;
                        $crate:: ver_int_len !()
                    ] >:: try_from(
                        data.get(
                            0..$crate:: ver_int_len !()
                        ).ok_or_else(
                            || loga::Error::new(
                                "Data length is less than version header size",
                                loga::ea!(got_len = data.len(), expected_len = $crate:: ver_int_len !()),
                            )
                        ) ?
                    ).unwrap()
                );
                match version {
                    $($ver => {
                        return Ok(Self:: $var(< $t >:: from_bytes(& data[$crate:: ver_int_len !()..]) ?));
                    },) * v => {
                        return Err(loga::Error::new("Unsupported version", loga::ea!(version = v)));
                    }
                }
            }
            pub fn to_bytes(&self) -> Vec < u8 > {
                let mut out = vec![];
                match self {
                    $(Self:: $var(d) => {
                        std:: io:: Write:: write(
                            &mut out,
                            &($ver as $crate:: utils:: versioned:: VerInt).to_le_bytes()
                        ).unwrap();
                        std::io::Write::write(&mut out, &d.to_bytes()).unwrap();
                    }),
                    *
                }
                return out;
            }
        }
        impl serde:: Serialize for $et {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer {
                if serializer.is_human_readable() {
                    return serializer.serialize_str(&zbase32::encode_full_bytes(&self.to_bytes()));
                } else {
                    return serde::Serialize::serialize(&self.to_bytes(), serializer);
                }
            }
        }
        impl < 'de > serde:: Deserialize < 'de > for $et {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de> {
                if deserializer.is_human_readable() {
                    let s = String::deserialize(deserializer)?;
                    Self::from_bytes(
                        &zbase32::decode_full_bytes_str(&s).map_err(serde::de::Error::custom)?,
                    ).map_err(
                        |e| serde::de::Error::custom(
                            format!("Error deserializing {} zbase32: {}", stringify!($et), e.to_string()),
                        ),
                    )
                } else {
                    let bytes = Vec::deserialize(deserializer)?;
                    return Ok(
                        Self::from_bytes(
                            &bytes,
                        ).map_err(
                            |e| serde::de::Error::custom(
                                format!("Error deserializing {}: {}", stringify!($et), e.to_string()),
                            ),
                        )?,
                    );
                }
            }
        }
    };
}
