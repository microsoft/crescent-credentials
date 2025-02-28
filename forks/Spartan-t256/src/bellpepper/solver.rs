
use ff::PrimeField;
use crate::bellpepper::r1cs::R1CSShape;
use crate::timer::Timer;
use crate::{InputsAssignment, Instance, R1CSInstance, VarsAssignment};

use bellpepper_core::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};

/// A `ConstraintSystem` which calculates witness values for a concrete instance of an R1CS circuit.
pub struct SatisfyingAssignment<F: PrimeField>
{
  // Assignments of variables
  pub(crate) input_assignment: Vec<F>,
  pub(crate) aux_assignment: Vec<F>,
}
use std::fmt;

impl<F: PrimeField> fmt::Debug for SatisfyingAssignment<F>
{
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("SatisfyingAssignment")
      .field("input_assignment", &self.input_assignment)
      .field("aux_assignment", &self.aux_assignment)
      .finish()
  }
}

impl<F: PrimeField> PartialEq for SatisfyingAssignment<F> {
  fn eq(&self, other: &SatisfyingAssignment<F>) -> bool {
    self.input_assignment == other.input_assignment && self.aux_assignment == other.aux_assignment
  }
}

impl<F: PrimeField> ConstraintSystem<F> for SatisfyingAssignment<F>
{
  type Root = Self;

  fn new() -> Self {
    let input_assignment = vec![F::ONE];

    Self {
      input_assignment,
      aux_assignment: vec![],
    }
  }

  fn alloc<Fn, A, AR>(&mut self, _: A, f: Fn) -> Result<Variable, SynthesisError>
  where
    Fn: FnOnce() -> Result<F, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.aux_assignment.push(f()?);

    Ok(Variable(Index::Aux(self.aux_assignment.len() - 1)))
  }

  fn alloc_input<Fn, A, AR>(&mut self, _: A, f: Fn) -> Result<Variable, SynthesisError>
  where
    Fn: FnOnce() -> Result<F, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.input_assignment.push(f()?);

    Ok(Variable(Index::Input(self.input_assignment.len() - 1)))
  }

  fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _a: LA, _b: LB, _c: LC)
  where
    A: FnOnce() -> AR,
    AR: Into<String>,
    LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
  {
    // Do nothing: we don't care about linear-combination evaluations in this context.
  }

  fn push_namespace<NR, N>(&mut self, _: N)
  where
    NR: Into<String>,
    N: FnOnce() -> NR,
  {
    // Do nothing; we don't care about namespaces in this context.
  }

  fn pop_namespace(&mut self) {
    // Do nothing; we don't care about namespaces in this context.
  }

  fn get_root(&mut self) -> &mut Self::Root {
    self
  }

  fn is_extensible() -> bool {
    true
  }

  fn extend(&mut self, other: &Self) {
    self.input_assignment
            // Skip first input, which must have been a temporarily allocated one variable.
            .extend(&other.input_assignment[1..]);
    self.aux_assignment.extend(other.aux_assignment.clone());
  }

  fn is_witness_generator(&self) -> bool {
    true
  }

  fn extend_inputs(&mut self, new_inputs: &[F]) {
    self.input_assignment.extend(new_inputs);
  }

  fn extend_aux(&mut self, new_aux: &[F]) {
    self.aux_assignment.extend(new_aux);
  }

  fn allocate_empty(
    &mut self,
    aux_n: usize,
    inputs_n: usize,
  ) -> (&mut [F], &mut [F]) {
    let allocated_aux = {
      let i = self.aux_assignment.len();
      self.aux_assignment.resize(aux_n + i, F::ZERO);
      &mut self.aux_assignment[i..]
    };

    let allocated_inputs = {
      let i = self.input_assignment.len();
      self.input_assignment.resize(inputs_n + i, F::ZERO);
      &mut self.input_assignment[i..]
    };

    (allocated_aux, allocated_inputs)
  }

  fn inputs_slice(&self) -> &[F] {
    &self.input_assignment
  }

  fn aux_slice(&self) -> &[F] {
    &self.aux_assignment
  }
}

#[allow(dead_code)]
impl<F: PrimeField> SatisfyingAssignment<F> {
  pub fn scalar_inputs(&self) -> Vec<F> {
    self.input_assignment.clone()
  }

  pub fn scalar_aux(&self) -> Vec<F> {
    self.aux_assignment.clone()
  }

  fn ff_element_to_Scalar(f : &F) -> crate::scalar::Scalar 
  {
    let repr = f.to_repr();
    let f_bytes : &[u8] = repr.as_ref();
    let mut fb : [u8; 32] = [0; 32];  
    for i in 0..32 {
      fb[i] = f_bytes[i];
    }
    crate::scalar::Scalar::from_bytes(&fb).unwrap()
  }

  pub fn r1cs_instance_and_witness(
    &self,
    shape: &R1CSShape<F>,
  ) -> (Instance, VarsAssignment, InputsAssignment) 
  {

    let mut W : Vec<crate::scalar::Scalar> = vec![];
    for wi in &self.aux_assignment {
       W.push(Self::ff_element_to_Scalar(wi));
    }
    let mut IO : Vec<crate::scalar::Scalar> = vec![];
    for io in &self.input_assignment {
       IO.push(Self::ff_element_to_Scalar(io));
    }

    let mut A : Vec<(usize, usize, crate::scalar::Scalar)> = vec![];
    let mut B : Vec<(usize, usize, crate::scalar::Scalar)> = vec![];
    let mut C : Vec<(usize, usize, crate::scalar::Scalar)> = vec![];

    for ai in &shape.A {
      A.push( ( ai.0, ai.1, Self::ff_element_to_Scalar(&ai.2) ) );
    }
    for bi in &shape.B {
      B.push( ( bi.0, bi.1, Self::ff_element_to_Scalar(&bi.2) ) );
    }
    for ci in &shape.C {
      C.push( ( ci.0, ci.1, Self::ff_element_to_Scalar(&ci.2) ) );
    }        

    Timer::print(&format!("Creating R1CSInstance with num_cons={}, num_vars={}, num_io={}", shape.num_cons, shape.num_vars, shape.num_io));
    let r1csinstance = R1CSInstance::new(shape.num_cons, shape.num_vars, shape.num_io, &A, &B, &C); 
    
    let witness = VarsAssignment::new_from_scalars(W).unwrap();
    let inputs = InputsAssignment::new_from_scalars(IO[1..IO.len()].to_vec()).unwrap();

    let digest = r1csinstance.get_digest().clone();
    let instance = Instance{inst: r1csinstance, digest};

    (instance, witness, inputs)
  }

}

