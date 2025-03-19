#!/bin/bash
cargo build --release && sudo RUST_LOG=info ./target/release/maybenot-tunnel
