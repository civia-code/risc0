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

#![no_main]

use json::parse;
use json_core::Outputs;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let from_email: String = env::read();
    let body: String = env::read();
    let processed_header: String = env::read();
    let signature: String = env::read();
    let email_svr_public_key: String = env::read();
    let email_hash = *Impl::hash_bytes(&from_email.as_bytes());

    let out = Outputs {
        email_svr_public_key: email_svr_public_key,
        email_hash: email_hash,
    };
    env::commit(&out);
}
