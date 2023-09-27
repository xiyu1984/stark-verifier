use halo2_proofs::arithmetic::Field;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use plonky2::field::{goldilocks_field::GoldilocksField, interpolation::barycentric_weights};

use crate::snark::chip::{
    goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
};

use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Clone, Debug)]
pub struct CosetInterpolationGateConstrainer {
    pub subgroup_bits: usize,
    pub degree: usize,
    pub barycentric_weights: Vec<Goldilocks>,
}

impl CosetInterpolationGateConstrainer {
    // pub fn new(subgroup_bits: usize) -> Self {
    //     Self::with_max_degree(subgroup_bits, 1 << subgroup_bits)
    // }

    // pub(crate) fn with_max_degree(subgroup_bits: usize, max_degree: usize) -> Self {
    //     assert!(max_degree > 1, "need at least quadratic constraints");

    //     let n_points = 1 << subgroup_bits;

    //     // Number of intermediate values required to compute interpolation with degree bound
    //     let n_intermediates = (n_points - 2) / (max_degree - 1);

    //     // Find minimum degree such that (n_points - 2) / (degree - 1) < n_intermediates + 1
    //     // Minimizing the degree this way allows the gate to be in a larger selector group
    //     let degree = (n_points - 2) / (n_intermediates + 1) + 2;

    //     let barycentric_weights = barycentric_weights(
    //         &<GoldilocksField as plonky2::field::types::Field>::two_adic_subgroup(subgroup_bits)
    //             .into_iter()
    //             .map(|x| (x, F::ZERO))
    //             .collect::<Vec<_>>(),
    //     );

    //     Self {
    //         subgroup_bits,
    //         degree,
    //         barycentric_weights,
    //     }
    // }

    fn num_points(&self) -> usize {
        1 << self.subgroup_bits
    }

    /// Wire index of the coset shift.
    pub(crate) fn wire_shift(&self) -> usize {
        0
    }

    fn start_values(&self) -> usize {
        1
    }

    /// Wire indices of the `i`th interpolant value.
    pub(crate) fn wires_value(&self, i: usize) -> Range<usize> {
        debug_assert!(i < self.num_points());
        let start = self.start_values() + i * D;
        start..start + D
    }

    fn start_evaluation_point(&self) -> usize {
        self.start_values() + self.num_points() * D
    }

    /// Wire indices of the point to evaluate the interpolant at.
    pub(crate) fn wires_evaluation_point(&self) -> Range<usize> {
        let start = self.start_evaluation_point();
        start..start + D
    }

    fn start_evaluation_value(&self) -> usize {
        self.start_evaluation_point() + D
    }

    /// Wire indices of the interpolated value.
    pub(crate) fn wires_evaluation_value(&self) -> Range<usize> {
        let start = self.start_evaluation_value();
        start..start + D
    }

    fn start_intermediates(&self) -> usize {
        self.start_evaluation_value() + D
    }

    pub fn num_routed_wires(&self) -> usize {
        self.start_intermediates()
    }

    fn num_intermediates(&self) -> usize {
        (self.num_points() - 2) / (self.degree - 1)
    }

    /// The wires corresponding to the i'th intermediate evaluation.
    fn wires_intermediate_eval(&self, i: usize) -> Range<usize> {
        debug_assert!(i < self.num_intermediates());
        let start = self.start_intermediates() + D * i;
        start..start + D
    }

    /// The wires corresponding to the i'th intermediate product.
    fn wires_intermediate_prod(&self, i: usize) -> Range<usize> {
        debug_assert!(i < self.num_intermediates());
        let start = self.start_intermediates() + D * (self.num_intermediates() + i);
        start..start + D
    }

    /// End of wire indices, exclusive.
    fn end(&self) -> usize {
        self.start_intermediates() + D * (2 * self.num_intermediates() + 1)
    }

    /// Wire indices of the shifted point to evaluate the interpolant at.
    fn wires_shifted_evaluation_point(&self) -> Range<usize> {
        let start = self.start_intermediates() + D * 2 * self.num_intermediates();
        start..start + D
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for CosetInterpolationGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut halo2wrong::RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>],
        local_wires: &[crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &crate::snark::types::assigned::AssignedHashValues<F>,
    ) -> Result<
        Vec<crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>>,
        halo2_proofs::plonk::Error,
    > {
        let mut constraints = Vec::new();

        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);

        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);

        let shift = &local_wires[self.wire_shift()];
        let evaluation_point =
            self.get_local_ext_algebra(local_wires, self.wires_evaluation_point());
        let shifted_evaluation_point =
            self.get_local_ext_algebra(local_wires, self.wires_shifted_evaluation_point());

        let neg_shift = goldilocks_extension_chip.scalar_mul(ctx, &shift, -Goldilocks::one())?;

        constraints.extend(
            goldilocks_extension_algebra_chip
                .scalar_mul_add_ext_algebra(
                    ctx,
                    &neg_shift,
                    &shifted_evaluation_point,
                    &evaluation_point,
                )?
                .to_ext_array(),
        );

        let base = goldilocks_extension_chip.two_extension(ctx)?;
        let domain =
            goldilocks_extension_chip.exp_power_of_2_extension(ctx, base, self.subgroup_bits)?;

        let values: Vec<
            crate::snark::chip::goldilocks_extension_algebra_chip::AssignedExtensionAlgebra<_>,
        > = (0..self.num_points())
            .map(|i| self.get_local_ext_algebra(local_wires, self.wires_value(i)))
            .collect::<Vec<_>>();

        let weights = &self.barycentric_weights;

        let initial_eval = goldilocks_extension_algebra_chip.zero_ext_algebra(ctx)?;
        let two = goldilocks_extension_chip.two_extension(ctx)?;
        let initial_prod = goldilocks_extension_algebra_chip.convert_to_ext_algebra(ctx, &two)?;

        let (mut computed_eval, mut computed_prod) = partial_interpolate_ext_algebra_target(
            builder,
            &domain[..self.degree],
            &values[..self.degree],
            &weights[..self.degree],
            shifted_evaluation_point,
            initial_eval,
            initial_prod,
        );

        for i in 0..self.num_intermediates() {
            let intermediate_eval =
                self.get_local_ext_algebra(local_wires, self.wires_intermediate_eval(i));
            let intermediate_prod =
                self.get_local_ext_algebra(local_wires, self.wires_intermediate_prod(i));
            constraints.extend(
                goldilocks_extension_algebra_chip
                    .sub_ext_algebra(ctx, &intermediate_eval, computed_eval)?
                    .to_ext_array(),
            );
            constraints.extend(
                goldilocks_extension_algebra_chip
                    .sub_ext_algebra(ctx, &intermediate_prod, computed_prod)?
                    .to_ext_array(),
            );

            let start_index = 1 + (self.degree - 1) * (i + 1);
            let end_index = (start_index + self.degree - 1).min(self.num_points());
            (computed_eval, computed_prod) = partial_interpolate_ext_algebra_target(
                builder,
                &domain[start_index..end_index],
                &values[start_index..end_index],
                &weights[start_index..end_index],
                shifted_evaluation_point,
                intermediate_eval,
                intermediate_prod,
            );
        }

        let evaluation_value =
            self.get_local_ext_algebra(local_wires, self.wires_evaluation_value());
        constraints.extend(
            goldilocks_extension_algebra_chip
                .sub_ext_algebra(ctx, &evaluation_value, computed_eval)?
                .to_ext_array(),
        );

        Ok(constraints)
    }
}