# rust-spectre
A Rust iteration of the Spectre Variant 1 attack formulated in my bachelor research. The original thesis' text explores the *feasibility of exploitation of the Spectre vulnerability in security-focused languages*, from which Rust is taken as a prime example.

Read the **thesis** text [here](./thesis.pdf).

A functioning **proof-of-concept** implementation of the attack is located [here](./src/main.rs).




**If you are new to Rust:**

* Install the Rust environment on your operating system along with Cargo, the Rust package manager.

* Download the repository. The `Cargo.toml` file and `src` directory alone are sufficient.

* Run
```bash
cargo build
cargo run
```
in the download directory.
