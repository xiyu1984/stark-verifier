# Command

## Evn

- install `solc`

    ```sh
    npm install -g solc
    ```

## Unit Test

```sh

cargo test --package semaphore_aggregation --lib -- plonky2_verifier::chip::hasher_chip::tests::test_hasher_chip_mock --exact --nocapture

```

```sh

# test_recursive_halo2_proof
cargo test -r --package semaphore_aggregation --lib -- plonky2_verifier::verifier_api::tests::test_recursive_halo2_proof --exact --nocapture

```
