//! Support for generating R1CS using bellperson.

#![allow(non_snake_case)]

use super::{shape_cs::ShapeCS, test_shape_cs::TestShapeCS};
use bellpepper_core::{Index, LinearCombination};
use ff::PrimeField;
use core::cmp::max;

/// A type that holds the shape of the R1CS matrices
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1CSShape<F: PrimeField> {
  pub num_cons: usize,
  pub num_vars: usize,
  pub num_io: usize,
  pub(crate) A: Vec<(usize, usize, F)>,
  pub(crate) B: Vec<(usize, usize, F)>,
  pub(crate) C: Vec<(usize, usize, F)>,
}

/// A type that holds a witness for a given R1CS instance
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1CSWitness<F: PrimeField> {
  W: Vec<F>,
}

impl<F: PrimeField> R1CSWitness<F> {
  pub fn new(witness : &Vec<F>) -> Self  {
    R1CSWitness{W: witness.to_vec()}
  }
}

impl<F: PrimeField> R1CSShape<F> {

    /// Pads the R1CSShape so that the number of variables is a power of two
  /// Renumbers variables to accomodate padded variables
  pub fn pad(&self) -> Self {
    // equalize the number of variables and constraints
    let m = max(self.num_vars, self.num_cons).next_power_of_two();

    // check if the provided R1CSShape is already as required
    if self.num_vars == m && self.num_cons == m {
      return self.clone();
    }

    // check if the number of variables are as expected, then
    // we simply set the number of constraints to the next power of two
    if self.num_vars == m {
      return R1CSShape {
        num_cons: m,
        num_vars: m,
        num_io: self.num_io,
        A: self.A.clone(),
        B: self.B.clone(),
        C: self.C.clone(),
      };
    }

    // otherwise, we need to pad the number of variables and renumber variable accesses
    let num_vars_padded = m;
    let num_cons_padded = m;
    let apply_pad = |M: &[(usize, usize, F)]| -> Vec<(usize, usize, F)> {
      M.iter()  // TODO: can use par_iter, make rayon non-optional, see Spartan2
        .map(|(r, c, v)| {
          (
            *r,
            if c >= &self.num_vars {
              c + num_vars_padded - self.num_vars
            } else {
              *c
            },
            *v,
          )
        })
        .collect::<Vec<_>>()
    };

    let A_padded = apply_pad(&self.A);
    let B_padded = apply_pad(&self.B);
    let C_padded = apply_pad(&self.C);

    R1CSShape {
      num_cons: num_cons_padded,
      num_vars: num_vars_padded,
      num_io: self.num_io,
      A: A_padded,
      B: B_padded,
      C: C_padded,
    }
  }
    
}

macro_rules! impl_r1cs_shape {
  ( $name:ident) => {
    impl<F: PrimeField> $name<F>
    {
      pub fn r1cs_shape(&self) -> R1CSShape<F> {
        let mut A: Vec<(usize, usize, F)> = Vec::new();
        let mut B: Vec<(usize, usize, F)> = Vec::new();
        let mut C: Vec<(usize, usize, F)> = Vec::new();

        let mut num_cons_added = 0;
        let mut X = (&mut A, &mut B, &mut C, &mut num_cons_added);

        let num_inputs = self.num_inputs();
        let num_constraints = self.num_constraints();
        let num_vars = self.num_aux();

        for constraint in self.constraints.iter() {
          add_constraint(
            &mut X,
            num_vars,
            &constraint.0,
            &constraint.1,
            &constraint.2,
          );
        }

        assert_eq!(num_cons_added, num_constraints);

        // Don't count One as an input for shape's purposes.
        let shape = R1CSShape{num_cons: num_constraints, num_vars: num_vars, num_io: num_inputs - 1, A, B, C};
        println!("Number of R1CS constraints before padding: {}", num_constraints);    
        shape.pad()
      }
    }
  };
}

impl_r1cs_shape!(ShapeCS);
impl_r1cs_shape!(TestShapeCS);

fn add_constraint<S: PrimeField>(
  X: &mut (
    &mut Vec<(usize, usize, S)>,
    &mut Vec<(usize, usize, S)>,
    &mut Vec<(usize, usize, S)>,
    &mut usize,
  ),
  num_vars: usize,
  a_lc: &LinearCombination<S>,
  b_lc: &LinearCombination<S>,
  c_lc: &LinearCombination<S>,
) {
  let (A, B, C, nn) = X;
  let n = **nn;
  let one = S::ONE;

  let add_constraint_component = |index: Index, coeff, V: &mut Vec<_>| {
    match index {
      Index::Input(idx) => {
        // Inputs come last, with input 0, reprsenting 'one',
        // at position num_vars within the witness vector.
        let i = idx + num_vars;
        V.push((n, i, one * coeff))
      }
      Index::Aux(idx) => V.push((n, idx, one * coeff)),
    }
  };

  for (index, coeff) in a_lc.iter() {
    add_constraint_component(index.0, coeff, A);
  }
  for (index, coeff) in b_lc.iter() {
    add_constraint_component(index.0, coeff, B)
  }
  for (index, coeff) in c_lc.iter() {
    add_constraint_component(index.0, coeff, C)
  }

  **nn += 1;
}
