# Updating Hardcoded data

- uncomment the `[[bin]]` section in the `Cargo.toml` file;

- make a backup copy of the assets and icons:

```
cp liquid_assets.json liquid_assets_.json
cp liquid_icons.json liquid_icons_.json
```

- launch the executable:

```
cargo run --bin make_hard_coded
```

- manually check changes:

```
diff <(jq --sort-keys . liquid_assets.json) <(jq --sort-keys . liquid_assets_.json)
diff <(jq --sort-keys . liquid_icons.json) <(jq --sort-keys . liquid_icons_.json)
```

- run the tests to make sure the new values have been serialized correctly and
  can be deserialized.
