// This file is copied and modified from Nova-Scotia/src/circom/circuit.rs

use bellpepper::gadgets::num::AllocatedNum;

use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, Circuit};
use ff::PrimeField;

// Store each row of A, B, and C, with the format (index, value)
pub type Constraint<Fr> = (Vec<(usize, Fr)>, Vec<(usize, Fr)>, Vec<(usize, Fr)>);

#[derive(Debug)]
pub struct R1CS<Fr: PrimeField> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraint<Fr>>,
}

#[derive(Debug)]
pub struct R1CSDimension {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
}

pub struct CircomCircuitSetup<Fr: PrimeField> {
    pub r1cs: R1CS<Fr>,
}

pub struct CircomCircuitProve<Fr: PrimeField> {
    pub r1cs_dimension: R1CSDimension,
    pub witness: Vec<Fr>,
}

impl<Fr: PrimeField> Circuit<Fr> for CircomCircuitSetup<Fr> {
    fn synthesize<CS: ConstraintSystem<Fr>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError> {
        let mut vars: Vec<AllocatedNum<Fr>> = vec![];

        // Assign the public inputs (and outputs)
        for i in 1..self.r1cs.num_inputs {
            let f: Fr = Fr::ONE;
            let v = AllocatedNum::alloc_input(cs.namespace(|| format!("public_{}", i)), || Ok(f))?;
            vars.push(v);
        }

        // Assign the private witnesses.
        for i in 0..self.r1cs.num_aux {
            let f: Fr = Fr::ONE;
            let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || Ok(f))?;
            vars.push(v);
        }

        // Compute <A[i], Z>, <B[i], Z>, <C[i], Z> for each constraint i,
        // where the vector Z = (1 || var).
        let make_lc = |lc_data: Vec<(usize, Fr)>| {
            let res = lc_data.iter().fold(
                LinearCombination::<Fr>::zero(),
                |lc: LinearCombination<Fr>, (index, coeff)| {
                    lc + if *index > 0 {
                        (*coeff, vars[*index - 1].get_variable())
                    } else {
                        (*coeff, CS::one())
                    }
                },
            );
            res
        };
        for (i, constraint) in self.r1cs.constraints.iter().enumerate() {
            cs.enforce(
                || format!("constraint {}", i),
                |_| make_lc(constraint.0.clone()),
                |_| make_lc(constraint.1.clone()),
                |_| make_lc(constraint.2.clone()),
            );
        }
        Ok(())
    }
}

impl<Fr: PrimeField> Circuit<Fr> for CircomCircuitProve<Fr> {
    fn synthesize<CS: ConstraintSystem<Fr>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError> {
        let witness = &self.witness;
        let mut vars: Vec<AllocatedNum<Fr>> = vec![];

        assert!(witness.len() == self.r1cs_dimension.num_inputs + self.r1cs_dimension.num_aux);

        // Assign the public inputs (and outputs)
        for i in 1..self.r1cs_dimension.num_inputs {
            let f: Fr = witness[i];
            let v = AllocatedNum::alloc_input(cs.namespace(|| format!("public_{}", i)), || Ok(f))?;
            vars.push(v);
        }

        // Assign the private witnesses.
        for i in 0..self.r1cs_dimension.num_aux {
            let f: Fr = witness[i + self.r1cs_dimension.num_inputs];
            let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || Ok(f))?;
            vars.push(v);
        }

        Ok(())
    }
}
