use std::time::Instant;

use anyhow::Result;
use itertools::Itertools;
use super::bn245_poseidon::plonky2_config::Bn254PoseidonGoldilocksConfig;
use super::types::{
    common_data::CommonData, proof::ProofValues, verification_key::VerificationKeyValues,
};
use super::verifier_circuit::{ProofTuple, Verifier};
use crate::plonky2_verifier::chip::native_chip::test_utils::create_proof_checked;
use crate::plonky2_verifier::chip::native_chip::utils::goldilocks_to_fe;
use colored::Colorize;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_solidity_verifier::compile_solidity;
use halo2_solidity_verifier::encode_calldata;
use halo2_solidity_verifier::BatchOpenScheme::Bdfg21;
use halo2_solidity_verifier::Evm;
use halo2_solidity_verifier::SolidityGenerator;
use log::info;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;

pub fn report_elapsed(now: Instant) {
    info!(
        "{}",
        format!("Took {} milliseconds", now.elapsed().as_millis())
            .blue()
            .bold()
    );
}

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
/// This runs only mock prover for constraint check
pub fn verify_inside_snark_mock(
    degree: u32,
    proof: ProofTuple<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>,
) {
    let (proof_with_public_inputs, vd, cd) = proof;
    // proof_with_public_inputs -> ProofValues type
    let proof = ProofValues::<Fr, 2>::from(proof_with_public_inputs.proof);
    let instances = proof_with_public_inputs
        .public_inputs
        .iter()
        .map(|e| goldilocks_to_fe(*e))
        .collect::<Vec<Fr>>();
    // let instances = vec![];
    let vk = VerificationKeyValues::from(vd.clone());
    let common_data = CommonData::from(cd);
    let verifier_circuit = Verifier::new(proof, instances.clone(), vk, common_data);
    let prover = MockProver::run(degree, &verifier_circuit, vec![instances.clone()]).unwrap();
    prover.assert_satisfied();
}

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
/// This runs real prover and generates valid SNARK proof, generates EVM verifier and runs the verifier
pub fn verify_inside_snark(
    degree: u32,
    proof: ProofTuple<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>, save: Option<String>
) {
    let (proof_with_public_inputs, vd, cd) = proof;
    let proof = ProofValues::<Fr, 2>::from(proof_with_public_inputs.proof);
    let instances = proof_with_public_inputs
        .public_inputs
        .iter()
        .map(|e| goldilocks_to_fe(*e))
        .collect::<Vec<Fr>>();
    let vk = VerificationKeyValues::from(vd.clone());
    let common_data = CommonData::from(cd);
    // runs mock prover
    let circuit = Verifier::new(proof, instances.clone(), vk, common_data);
    let mock_prover = MockProver::run(degree, &circuit, vec![instances.clone()]).unwrap();
    mock_prover.assert_satisfied();
    info!("{}", "Mock prover passes".green().bold());
    // generates halo2 solidity verifier
    let mut rng = rand::thread_rng();
    let param = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let kzg_param:&ParamsKZG<Bn256> = &param;
    let vk = keygen_vk(kzg_param, &circuit).unwrap();
    let pk = keygen_pk(kzg_param, vk.clone(), &circuit).unwrap();
    let generator = SolidityGenerator::new(kzg_param, &vk, Bdfg21, instances.len());
    let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
    let mut evm = Evm::default();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);
    // generates SNARK proof and runs EVM verifier
    info!("{}", "Starting finalization phase".blue().bold());
    let now = Instant::now();
    // add blindness
    let proof = create_proof_checked(kzg_param, &pk, circuit.clone(), &instances, &mut rng);
    info!("{}", "SNARK proof generated successfully!".green().bold());
    report_elapsed(now);
    let calldata = encode_calldata(Some(vk_address.into()), &proof, &instances);
    let (gas_cost, _output) = evm.call(verifier_address, calldata);
    info!("{}", format!("Gas cost: {}", gas_cost).yellow().bold());

    if let Some(save_path) = save {
        // save verifier and vk as solidity smart contract
        std_ops::save_solidity(format!("{}_verifier.sol", save_path), &verifier_solidity);
        std_ops::save_solidity(format!("{}_vk.sol", save_path), &vk_solidity);
    }
}

pub fn verify_inside_snark_solidity(
    degree: u32,
    proof: ProofTuple<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>, kzg_param: &ParamsKZG<Bn256>, save: Option<String>
) -> Result<(Vec<u8>, Vec<Fr>)> {
    let (proof_with_public_inputs, vd, cd) = proof;
    let proof = ProofValues::<Fr, 2>::from(proof_with_public_inputs.proof);
    let instances = proof_with_public_inputs
        .public_inputs
        .iter()
        .map(|e| goldilocks_to_fe(*e))
        .collect::<Vec<Fr>>();
    let vk = VerificationKeyValues::from(vd.clone());
    let common_data = CommonData::from(cd);
    // runs mock prover
    let circuit = Verifier::new(proof, instances.clone(), vk, common_data);
    let mock_prover = MockProver::run(degree, &circuit, vec![instances.clone()]).unwrap();
    mock_prover.assert_satisfied();
    info!("{}", "Mock prover passes".green().bold());
    // generates halo2 solidity verifier
    let vk = keygen_vk(kzg_param, &circuit).unwrap();
    let pk = keygen_pk(kzg_param, vk.clone(), &circuit).unwrap();
    let generator = SolidityGenerator::new(kzg_param, &vk, Bdfg21, instances.len());
    let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
    let mut evm = Evm::default();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);
    // generates SNARK proof and runs EVM verifier
    info!("{}", "Starting finalization phase".blue().bold());
    let now = Instant::now();
    // add blindness
    let mut rng = rand::thread_rng();
    let proof = create_proof_checked(kzg_param, &pk, circuit.clone(), &instances, &mut rng);
    info!("{}", "SNARK proof generated successfully!".green().bold());
    report_elapsed(now);
    let calldata = encode_calldata(Some(vk_address.into()), &proof, &instances);
    let (gas_cost, _output) = evm.call(verifier_address, calldata);
    info!("{}", format!("Gas cost: {}", gas_cost).yellow().bold());

    if let Some(save_path) = save {
        // save verifier and vk as solidity smart contract
        std_ops::save_solidity(format!("{}_verifier.sol", save_path), &verifier_solidity);
        std_ops::save_solidity(format!("{}_vk.sol", save_path), &vk_solidity);
    }

    Ok((proof, instances))
}

pub fn make_checked_fri2kzg_snark_proof(
    // degree: u32,
    proof: ProofTuple<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>, kzg_param: &ParamsKZG<Bn256>, save: Option<String>
) -> Result<(Vec<u8>, Vec<Fr>)> {
    let (proof_with_public_inputs, vd, cd) = proof;
    let proof = ProofValues::<Fr, 2>::from(proof_with_public_inputs.proof);
    let instances = proof_with_public_inputs
        .public_inputs
        .iter()
        .map(|e| goldilocks_to_fe(*e))
        .collect::<Vec<Fr>>();
    let vk = VerificationKeyValues::from(vd.clone());
    let common_data = CommonData::from(cd);
    // runs mock prover
    let circuit = Verifier::new(proof, instances.clone(), vk, common_data);
    // let mock_prover = MockProver::run(degree, &circuit, vec![instances.clone()]).unwrap();
    // mock_prover.assert_satisfied();
    // info!("{}", "Mock prover passes".green().bold());
    // generates halo2 solidity verifier
    let vk = keygen_vk(kzg_param, &circuit).unwrap();
    let pk = keygen_pk(kzg_param, vk.clone(), &circuit).unwrap();
    info!("{}", "Starting generate checked proof".blue().bold());
    let now = Instant::now();
    // add blindness
    let mut rng = rand::thread_rng();
    let proof = create_proof_checked(kzg_param, &pk, circuit.clone(), &instances, &mut rng);
    info!("{}", "SNARK proof generated successfully!".green().bold());
    report_elapsed(now);

    if let Some(save_path) = save {
        // save verifier and vk as solidity smart contract
        std_ops::save_snark_proof(format!("{}_snark_proof.json", save_path), &proof);
        let u64_instances = proof_with_public_inputs.public_inputs.iter().map(|ins| {
            ins.to_canonical_u64().to_string()
        }).collect_vec();
        std_ops::save_snark_instances(format!("{}_snark_instances.json", save_path), &u64_instances);
    }

    Ok((proof, instances))
}

pub mod std_ops {
    use std::io::Read;
    pub(crate) use std::{
        fs::{create_dir_all, File, self},
        io::Write
    };

    use anyhow::Result;

    const DIR_GENERATED: &str = "./generated-sc";
    const DIR_SNARKPROOF: &str = "./snark-proof";

    pub(crate) fn save_solidity(name: impl AsRef<str>, solidity: &str) {
        create_dir_all(DIR_GENERATED).unwrap();
        File::create(format!("{DIR_GENERATED}/{}", name.as_ref()))
            .unwrap()
            .write_all(solidity.as_bytes())
            .unwrap();
    }

    pub fn load_solidity(name: impl AsRef<str>) -> Result<String> {
        let mut f = File::open(format!("{}/{}", DIR_GENERATED, name.as_ref()))?;
        let mut buffer = String::new();
        f.read_to_string(&mut buffer)?;
        Ok(buffer)
    }

    pub(crate) fn save_snark_proof(name: impl AsRef<str>, proof: &Vec<u8>) {
        let proof_json = serde_json::to_string(&proof).unwrap();
        create_dir_all(DIR_SNARKPROOF).unwrap();
        fs::write(format!("{}/{}", DIR_SNARKPROOF, name.as_ref()), proof_json).expect("Unable to write `snark proof` to file");
    }

    pub fn load_snark_proof(name: impl AsRef<str>) -> Result<Vec<u8>, serde_json::Error> {
        let proof_json = fs::read(format!("{}/{}", DIR_SNARKPROOF, name.as_ref())).expect(&format!("load proof {} error", name.as_ref()));
        serde_json::from_slice(&proof_json)
    }

    pub(crate) fn save_snark_instances(name: impl AsRef<str>, instances: &Vec<String>) {
        let instances_json = serde_json::to_string(instances).expect(&format!("load instances {} error", name.as_ref()));
        create_dir_all(DIR_SNARKPROOF).unwrap();
        fs::write(format!("{}/{}", DIR_SNARKPROOF, name.as_ref()), instances_json).expect("Unable to write `snark instances` to file");
    }

    pub fn load_snark_instances(name: impl AsRef<str>) -> Result<Vec<String>, serde_json::Error> {
        let instances_json = fs::read(format!("{}/{}", DIR_SNARKPROOF, name.as_ref())).unwrap();
        serde_json::from_slice(&instances_json)
    }
}

#[cfg(test)]
mod tests {
    use log::{info, LevelFilter};

    use super::{verify_inside_snark, verify_inside_snark_mock};
    use crate::plonky2_verifier::{
        bn245_poseidon::plonky2_config::{
            standard_inner_stark_verifier_config, standard_stark_verifier_config,
            Bn254PoseidonGoldilocksConfig,
        },
        verifier_circuit::ProofTuple,
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{
            hashing::hash_n_to_hash_no_pad,
            poseidon::{PoseidonHash, PoseidonPermutation},
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
    };

    type F = GoldilocksField;
    const D: usize = 2;

    fn generate_proof_tuple() -> ProofTuple<F, Bn254PoseidonGoldilocksConfig, D> {
        let (inner_target, inner_data) = {
            let hash_const =
                hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[F::from_canonical_u64(42)]);
            let mut builder = CircuitBuilder::<F, D>::new(standard_inner_stark_verifier_config());
            let target = builder.add_virtual_target();
            let expected_hash = builder.constant_hash(hash_const);
            let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![target]);
            builder.connect_hashes(hash, expected_hash);
            builder.register_public_inputs(&expected_hash.elements);
            let data = builder.build::<PoseidonGoldilocksConfig>();
            (target, data)
        };

        let mut builder = CircuitBuilder::<F, D>::new(standard_stark_verifier_config());
        let proof_t =
            builder.add_virtual_proof_with_pis(&inner_data.common);
        let vd = builder.constant_verifier_data(&inner_data.verifier_only);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&proof_t, &vd, &inner_data.common);
        builder.register_public_inputs(&proof_t.public_inputs);
        let data = builder.build::<Bn254PoseidonGoldilocksConfig>();

        let proof = {
            let mut pw = PartialWitness::new();
            pw.set_target(inner_target, F::from_canonical_usize(42));
            inner_data.prove(pw).unwrap()
        };

        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&proof_t, &proof);
        let final_proof = data.prove(pw).unwrap();
        let proof: ProofTuple<F, Bn254PoseidonGoldilocksConfig, D> =
            (final_proof, data.verifier_only, data.common);
        proof
    }

    #[test]
    fn test_recursive_halo2_mock() {
        let proof = generate_proof_tuple();
        verify_inside_snark_mock(19, proof);
    }

    #[test]
    fn test_recursive_halo2_proof() {
        let mut log_builder = env_logger::Builder::from_default_env();
        log_builder.format_timestamp(None);
        log_builder.filter_level(LevelFilter::Info);
        let _ = log_builder.try_init();

        info!("generate proof tuple");
        let proof = generate_proof_tuple();

        info!("start verify in snark");
        verify_inside_snark(19, proof, None);
    }
}
