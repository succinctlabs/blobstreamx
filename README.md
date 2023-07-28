# zkqgb

Set release version to old nightly.

```
cargo +nightly-2023-05-29 build
```

## Fixtures

Generating celestia consensus signatures
```
cargo run get-celestia-consensus-signatures
```


Generating validator hashes
```
cargo run generate-val-array --validators {number of validators}
```
