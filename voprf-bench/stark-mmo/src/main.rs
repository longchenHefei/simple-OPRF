//! STARK prove/verify CLI for GC-VOPRF E2E.
//!
//! Statement: Fibonacci-style iterative computation of length N (power of two),
//! 2 terms per row (winterfell fib_small AIR). Used as a runnable stand-in for
//! the paper's MMO/AES-garbling STARK (public verify); not a full AES-circuit AIR.

use clap::{Parser, Subcommand};
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::Instant;
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, hashers::Blake3_256},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, Proof, ProofOptions, Prover,
    Serializable, Deserializable, SliceReader, StarkDomain, Trace, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree, AcceptableOptions,
};

const TRACE_WIDTH: usize = 2;
const DEFAULT_SEQ_LEN: usize = 2048; // power of two; ~ms verify on small VMs

type Hasher = Blake3_256<BaseElement>;

#[derive(Parser)]
#[command(name = "stark-mmo")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Prove {
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,
        /// Fibonacci sequence length (power of two)
        #[arg(long, default_value_t = DEFAULT_SEQ_LEN)]
        n: usize,
    },
    Verify {
        #[arg(short, long, default_value = "proof.bin")]
        input: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove { output, n } => do_prove(&output, n),
        Cmd::Verify { input } => do_verify(&input),
    }
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,  // queries
        8,   // blowup
        0,   // grinding_factor
        winterfell::FieldExtension::None,
        8,   // fri_folding_factor
        255, // fri_remainder_max_degree (2^k - 1)
    )
}

fn do_prove(path: &PathBuf, n: usize) {
    assert!(n.is_power_of_two() && n >= 8, "n must be power of two >= 8");
    let options = proof_options();
    let prover = FibProver::<Hasher>::new(options);
    let trace = prover.build_trace(n);
    let result = prover.get_pub_inputs(&trace);

    let t0 = Instant::now();
    let proof = prover.prove(trace).expect("prove");
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // File: [u64 n LE][u64 result LE][proof bytes]
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(n as u64).to_le_bytes());
    bytes.extend_from_slice(&result.as_int().to_le_bytes());
    proof.write_into(&mut bytes);

    fs::write(path, &bytes).expect("write");
    println!("prove_ms: {:.3}", prove_ms);
    println!("proof_bytes: {}", bytes.len());
    println!("n: {}", n);
    println!("digest: {:016x}", result.as_int());
}

fn do_verify(path: &PathBuf) {
    let bytes = fs::read(path).expect("read");
    assert!(bytes.len() > 16, "proof file too short");
    let n = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
    let result_int = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let result = BaseElement::new(result_int);
    let mut reader = SliceReader::new(&bytes[16..]);
    let proof = Proof::read_from(&mut reader).expect("deserialize proof");

    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    let t0 = Instant::now();
    winterfell::verify::<FibAir, Hasher, DefaultRandomCoin<Hasher>>(proof, result, &acceptable)
        .expect("verify failed");
    let verify_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!("verify_ms: {:.3}", verify_ms);
    println!("proof_bytes: {}", bytes.len());
    println!("n: {}", n);
    println!("digest: {:016x}", result_int);
    println!("verify: ok");
}

// ----- AIR -----

struct FibAir {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for FibAir {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseField, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        Self {
            context: AirContext::new(trace_info, degrees, 3, options),
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        result[0] = next[0] - (current[0] + current[1]);
        result[1] = next[1] - (current[1] + next[0]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, Self::BaseField::ONE),
            Assertion::single(1, 0, Self::BaseField::ONE),
            Assertion::single(1, last_step, self.result),
        ]
    }
}

// ----- Prover -----

struct FibProver<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> FibProver<H> {
    fn new(options: ProofOptions) -> Self {
        Self {
            options,
            _hasher: PhantomData,
        }
    }

    fn build_trace(&self, sequence_length: usize) -> TraceTable<BaseElement> {
        let mut trace = TraceTable::new(TRACE_WIDTH, sequence_length / 2);
        trace.fill(
            |state| {
                state[0] = BaseElement::ONE;
                state[1] = BaseElement::ONE;
            },
            |_, state| {
                state[0] += state[1];
                state[1] += state[0];
            },
        );
        trace
    }
}

impl<H> Prover for FibProver<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    type BaseField = BaseElement;
    type Air = FibAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(1, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}
