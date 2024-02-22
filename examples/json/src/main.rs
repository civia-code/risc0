// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//use json_core::Outputs;
use json_methods::SEARCH_JSON_ELF;
use json_methods::SEARCH_JSON_ID;
use risc0_zkvm::{
    default_prover,
    serde::{ to_vec},
    ExecutorEnv,
};
//use std::mem;

fn main() {
    let from_email = String::from("flalidji@yahoo.fr");
    let body = String::from("------=_Part_846214_1310223187.1572979158327\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\ntest\r\n\r\n------=_Part_846214_1310223187.1572979158327\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n<html><head></head><body><div class=\"yahoo-style-wrap\" style=\"font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:13px;\"><div dir=\"ltr\" data-setdir=\"false\">test<br></div></div></body></html>\r\n------=_Part_846214_1310223187.1572979158327--\r\n");
    let processed_header = String::from("date:Tue, 5 Nov 2019 18:39:18 +0000 (UTC)\r\nfrom:FAYCAL LALIDJI <flalidji@yahoo.fr>\r\nto:\"stivennoni77@gmail.com\" <stivennoni77@gmail.com>\r\nsubject:test\r\nreferences:<1987505120.846215.1572979158328.ref@mail.yahoo.com>\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.fr; s=s2048; t=1572979163; bh=PwzV/OmVqbbZ9nbsk59cdtyIPAw1oeFgmBzN3uHGq6o=; h=Date:From:To:Subject:References:From:Subject; b=");
    let signature = String::from("ow1pNdLLp6K9zb7B02m3czD06q+Xo7bL09dyr2QJ/H0pPN6CEj3G36IKt42o9uqaEtw+ZH37Iw5lazQqO8ndeq7bbXTMC5v6N1718z7rAzO/BDQqg6J3hoJ3QEodhWczh0ouhJmc+DeZtpB7yLee/DqHmySV9/xKrKaMoxp7GLpIRVJkK5FsgnViFzhZ0l4ac99/eOrRdqnxQ6HBBx4NXdVGMfOYT9jCFGxOnOrH9gMP8UD7I5QJKGKlDdNm/D1Ue0nTUr06+R1YpDNOXBnXj3tK1sBW9EFHZ4nfmydxSpR0aMUec+k4Wou1AC+t2W/zOaATkCb5VftwOwBnLSD8pQ==");
    let email_svr_public_key= String::from("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoWufgbWw58MczUGbMv176RaxdZGOMkQmn8OOJ/HGoQ6dalSMWiLaj8IMcHC1cubJx2gziAPQHVPtFYayyLA4ayJUSNk10/uqfByiU8qiPCE4JSFrpxflhMIKV4bt+g1uHw7wLzguCf4YAoR6XxUKRsAoHuoF7M+v6bMZ/X1G+viWHkBl4UfgJQ6O8F1ckKKoZ5KqUkJH5pDaqbgs+F3PpyiAUQfB6EEzOA1KMPRWJGpzgPtKoukDcQuKUw9GAul7kSIyEcizqrbaUKNLGAmz0elkqRnzIsVpz6jdT1/YV5Ri6YUOQ5sN5bqNzZ8TxoQlkbVRy6eKOjUnoSSTmSAhwIDAQAB");
    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&from_email).unwrap())
        .add_input(&to_vec(&body).unwrap())
        .add_input(&to_vec(&processed_header).unwrap())
        .add_input(&to_vec(&signature).unwrap())
        .add_input(&to_vec(&email_svr_public_key).unwrap())
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(env, SEARCH_JSON_ELF).unwrap();
    println!("{:?}", receipt);
    //let size = mem::size_of_val(&receipt);
    //println!("Size of receipt: {} bytes", size);
    receipt.verify(SEARCH_JSON_ID).unwrap();
}

/*fn main() {
    let data = include_str!("../res/example.json");
    let outputs = search_json(data);
    println!();
    println!("  {:?}", outputs.hash);
    println!(
        "provably contains a field 'critical_data' with value {}",
        outputs.data
    );
}

fn search_json(data: &str) -> Outputs {
    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&data).unwrap())
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(env, SEARCH_JSON_ELF).unwrap();
    //let size = mem::size_of_val(&receipt);
    //println!("Size of receipt: {} bytes", size);
    println!("{:?}", receipt);

    from_slice(&receipt.journal).unwrap()
}

#[cfg(test)]
mod tests {
    #[test]
    fn main() {
        let data = include_str!("../res/example.json");
        let outputs = super::search_json(data);
        assert_eq!(
            outputs.data, 47,
            "Did not find the expected value in the critical_data field"
        );
    }
}
*/