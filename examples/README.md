# Examples

Run examples with:

```bash
cargo run --example basic_config -- ./config.toml
cargo run --example runtime_no_alloc
cargo run --example timing_profile
```

Files:
- `basic_config.rs`: async load + validate config
- `runtime_no_alloc.rs`: convert to runtime no-allocation API and derive artifact tag
- `timing_profile.rs`: switch centralized timing profile (`Balanced`/`Hardened`)
