
use crate::group::GroupElement as C;
use crate::scalar::Scalar as F;


// Represent each base symbolically, as (bases, scalars), such that base = msm(bases, scalars)
// When we later use the base in an MSM, say as base^x, we compute (bases, x*scalars) and
// add this list of terms (bases[1]^scalars[1], ..., ) as terms in the MSM
#[derive(Clone)]
pub struct IPABases<C, F>{
    bases: Vec<Vec<C>>,
    scalars: Vec<Vec<F>>,
}

impl IPABases<C, F>
{
    pub fn new(n: usize) -> Self {
        let bases = Vec::with_capacity(n);
        let scalars = Vec::with_capacity(n);
        IPABases { bases, scalars}
    }

    pub fn defer_init(&mut self, scalars : &[F], bases: &[C]){
        assert!(scalars.len() == bases.len(), "Scalars and bases must have same length");
        self.scalars.push(scalars.to_vec());
        self.bases.push(bases.to_vec());
    }

    // self is the left half
    // Update G_L[i] to  G_L[i] * scalars[0], (just update the scalars, don't actually compute the scalar mult)
    // then append G_R[i] * scalars[1], (again not the scalar mult)
    pub fn defer(&mut self, i : usize, bases_R : &Self, scalars : &[F]){

        assert!(scalars.len() == 2);

        for k in 0..self.scalars[i].len() {
            self.scalars[i][k] *= scalars[0];
        }

        for k in 0..bases_R.bases[i].len() {
            self.scalars[i].push(bases_R.scalars[i][k] * scalars[1]);
            self.bases[i].push(bases_R.bases[i][k]); 
        }
    }

    /// Split the bases at the given index, returning two separate IPABases
    /// structures representing the left and right halves
    pub fn split_at(&self, n: usize) -> (Self, Self) {
        assert!(n <= self.bases.len(), "Split index out of bounds");
                
        // Create new instances for left and right parts
        let mut left = Self::new(n);
        let mut right = Self::new(self.bases.len() - n);
        for i in 0..n {
            left.bases.push(self.bases[i].clone());
            left.scalars.push(self.scalars[i].clone());
        }
        
        for i in 0..(self.bases.len() - n) {
            right.bases.push(self.bases[n + i].clone());
            right.scalars.push(self.scalars[n + i].clone());
        }
        
        (left, right)
    }

    /// Get the scalars and bases associated with the given values
    /// 
    /// This method takes a slice of scalars and returns a tuple containing:
    /// 1. A vector of scalars (combining the input scalars with the internal scalars)
    /// 2. A vector of bases (corresponding bases for the scalars)
    pub fn get(&self, values: &[F]) -> (Vec<F>, Vec<C>) {
        assert!(values.len() == self.bases.len(), "Input length must match bases length");
        
        let mut result_scalars = Vec::with_capacity(values.len());
        let mut result_bases = Vec::with_capacity(values.len());
        
        for (i, value) in values.iter().enumerate() {
            // For each scalar in the input, we multiply it with all stored scalars
            // for the corresponding base and add to the result
            for j in 0..self.scalars[i].len() {
                result_scalars.push(*value * self.scalars[i][j]);
                result_bases.push(self.bases[i][j]);
            }
        }
        
        (result_scalars, result_bases)
    }    

   

}