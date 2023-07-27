use std::fmt;

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_x509::{AlgorithmIdentifier, DigestInfo};

use crate::{Error, ErrorKind, Result};

pub enum SmartCardApi {
    WinSCard(Card),
}

impl fmt::Debug for SmartCardApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WinSCard { .. } => f.debug_tuple("SmartCardApi::WinSCard").finish(),
        }
    }
}

#[derive(Debug)]
pub struct SmartCard {
    smart_card_type: SmartCardApi,
    pin: Vec<u8>,
}

impl SmartCard {
    pub fn new(pin: Vec<u8>, scard_reader_name: &str) -> Result<Self> {
        let context = Context::establish(Scope::User)?;
        let readers_len = context.list_readers_len()?;
        let mut buff = vec![0_u8; readers_len];
        let mut names = context.list_readers(&mut buff)?;

        let reader_name = names
            .find(|reader_name| reader_name.to_bytes() == scard_reader_name.as_bytes())
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Provided smart card reader does not exist."))?;

        let scard = context.connect(reader_name, ShareMode::Shared, Protocols::T1)?;

        Ok(Self {
            smart_card_type: SmartCardApi::WinSCard(scard),
            pin,
        })
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match &self.smart_card_type {
            SmartCardApi::WinSCard(scard) => {
                // https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
                const APDU_RESPONSE_OK: [u8; 2] = [0x90, 0x00];

                // This control code is extracted from the API calls recording to the WinSCard API
                scard.control(0x00313520, &[], &mut [])?;

                let mut result_buff = [0; 128];
                let output = scard.transmit(
                    &[
                        // apdu header
                        0x00, 0xa4, 0x00, 0x0c, // data len
                        0x02, // data
                        0x3f, 0xff,
                    ],
                    &mut result_buff,
                )?;
                if output != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                let mut pin_apdu = vec![
                    // command header
                    0x00,
                    0x20,
                    0x00,
                    0x80,
                    // pin len
                    self.pin.len().try_into().unwrap(),
                ];
                pin_apdu.extend_from_slice(&self.pin);

                let output = scard.transmit(&pin_apdu, &mut result_buff)?;

                if output != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                let output = scard.transmit(
                    &[
                        // apdu header
                        0x00, 0x22, 0x41, 0xb6, // data len
                        0x06, // data
                        0x80, 0x01, 0x57, 0x84, 0x01, 0x82,
                    ],
                    &mut result_buff,
                )?;
                if output != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                let mut signature_buff = vec![0; 300];
                let output = scard.transmit(&build_data_sign_apdu(data)?, &mut signature_buff)?;
                // the last two bytes is status bytes
                let output_len = output.len();
                if &output[output_len - 2..] != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                // the last two bytes is status bytes
                let signature = output[..(output_len - 2)].to_vec();

                let _output = scard.transmit(
                    &[
                        // apdu header
                        0x00, 0x20, 0x00, 0x82,
                    ],
                    &mut result_buff,
                )?;

                Ok(signature)
            }
        }
    }
}

fn build_data_sign_apdu(data_to_sign: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let mut sign_data_apdu = vec![
        // apdu header
        0x00, 0x2a, 0x9e, 0x9a, // data length
        0x00, 0x00,
    ];

    let data_to_sign = DigestInfo {
        oid: AlgorithmIdentifier::new_sha1(),
        digest: OctetStringAsn1::from(data_to_sign.as_ref().to_vec()),
    };
    let encoded_data = picky_asn1_der::to_vec(&data_to_sign)?;

    sign_data_apdu.push(encoded_data.len().try_into().unwrap());
    sign_data_apdu.extend_from_slice(&encoded_data);

    // expected output length
    // we don't know the resulting signature len so we set [0x00 0x00] here
    sign_data_apdu.extend_from_slice(&[0x00, 0x00]);

    Ok(sign_data_apdu)
}

#[cfg(test)]
mod tests {
    use pcsc::{Context, Scope};
    use sha1::{Digest, Sha1};

    use super::SmartCard;

    #[test]
    fn run() {
        let data_to_sign = [
            49_u8, 61, 48, 22, 6, 9, 42, 134, 72, 134, 247, 13, 1, 9, 3, 49, 9, 6, 7, 43, 6, 1, 5, 2, 3, 1, 48, 35, 6,
            9, 42, 134, 72, 134, 247, 13, 1, 9, 4, 49, 22, 4, 20, 22, 144, 59, 22, 68, 47, 213, 64, 69, 126, 237, 38,
            151, 109, 213, 92, 122, 198, 202, 21,
        ];
        let mut sha1 = Sha1::new();
        sha1.update(&data_to_sign);
        let data_to_sign = sha1.finalize().to_vec();

        println!("data to sign: {:?}", data_to_sign);

        let expected_signature = [
            16_u8, 72, 236, 185, 169, 67, 103, 61, 147, 20, 88, 198, 7, 245, 226, 138, 7, 104, 68, 169, 60, 51, 19,
            138, 191, 107, 30, 236, 118, 28, 236, 193, 47, 203, 31, 232, 194, 70, 127, 74, 243, 3, 135, 113, 207, 86,
            135, 254, 180, 142, 82, 143, 66, 62, 26, 128, 118, 76, 136, 182, 64, 201, 24, 109, 205, 2, 11, 38, 20, 23,
            174, 181, 77, 185, 70, 251, 127, 138, 3, 71, 203, 81, 106, 206, 141, 190, 157, 114, 141, 102, 255, 223,
            247, 118, 165, 202, 132, 129, 245, 223, 35, 20, 57, 221, 183, 195, 39, 247, 239, 194, 145, 127, 30, 95, 82,
            143, 173, 211, 200, 107, 54, 199, 211, 146, 177, 41, 101, 251, 253, 184, 13, 147, 150, 216, 145, 186, 37,
            179, 47, 198, 114, 15, 195, 236, 209, 57, 90, 29, 200, 233, 207, 105, 185, 81, 10, 89, 26, 132, 82, 97,
            239, 207, 74, 32, 178, 57, 86, 220, 10, 116, 199, 206, 77, 122, 94, 113, 174, 11, 64, 125, 254, 22, 198,
            238, 195, 27, 86, 199, 211, 89, 106, 136, 4, 201, 150, 21, 157, 72, 7, 21, 117, 159, 111, 166, 211, 223,
            25, 166, 217, 5, 50, 61, 74, 192, 202, 1, 115, 130, 71, 65, 99, 54, 31, 142, 99, 150, 229, 175, 135, 55,
            152, 43, 222, 238, 91, 46, 204, 115, 94, 231, 141, 68, 86, 120, 227, 154, 225, 252, 37, 91, 148, 206, 96,
            185, 198, 108,
        ];

        let smart_card = SmartCard::new(b"214653214653".to_vec(), "Microsoft Virtual Smart Card 0").unwrap();
        let signature = smart_card.sign(&data_to_sign).unwrap();
        println!(
            "{:0x?} {}",
            signature,
            signature.as_slice() == expected_signature.as_slice()
        );
    }

    #[test]
    fn readers() {
        let context = Context::establish(Scope::User).unwrap();
        let readers_len = context.list_readers_len().unwrap();
        let mut buff = vec![0_u8; readers_len];
        let names = context.list_readers(&mut buff).unwrap();
        for name in names {
            println!("{:?}", name);
        }
    }
}
