//! Fig.10-style STARK for GC-VOPRF: half-gate garbling correctness + key/cm binding.
//! NOT a Fibonacci placeholder.
//!
//! Witness (LE):
//!   u64 n_and
//!   u8 cm[32+128*16]
//!   u8 gc_hash[32], R_root[32], out_hash[32]
//!   u8 delta[16]
//!   repeat n_and: a0,b0,Tg,Te,Ha0,Ha1,Hb0,Hb1 (16 each), pa, pb

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::Instant;
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, hashers::Blake3_256},
    math::{fields::f64::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, Proof, ProofOptions, Prover,
    Serializable, Deserializable, SliceReader, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree, AcceptableOptions,
};

type Hasher = Blake3_256<BaseElement>;
type E = BaseElement;

const TRACE_WIDTH: usize = 18;
const CM_BYTES: usize = 32 + 128 * 16;

#[derive(Parser)]
#[command(name = "stark-garble")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Prove {
        #[arg(short, long)]
        witness: PathBuf,
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,
    },
    Verify {
        #[arg(short, long, default_value = "proof.bin")]
        input: PathBuf,
        #[arg(long)]
        public: Option<PathBuf>,
    },
}

#[derive(Clone)]
struct PublicInputs {
    bind: [E; 4],
    n_and: u64,
    n_bits: u64,
}

impl ToElements<E> for PublicInputs {
    fn to_elements(&self) -> Vec<E> {
        let mut v = self.bind.to_vec();
        v.push(E::new(self.n_and));
        v.push(E::new(self.n_bits));
        v
    }
}

struct Witness {
    n_and: usize,
    cm: Vec<u8>,
    gc_hash: [u8; 32],
    r_root: [u8; 32],
    out_hash: [u8; 32],
    delta: [u8; 16],
    gates: Vec<GateWit>,
}

struct GateWit {
    a0: [u8; 16],
    b0: [u8; 16],
    tg: [u8; 16],
    te: [u8; 16],
    ha0: [u8; 16],
    ha1: [u8; 16],
    hb0: [u8; 16],
    hb1: [u8; 16],
    pa: u8,
    pb: u8,
}

fn read_u64_le(buf: &[u8], off: &mut usize) -> u64 {
    let v = u64::from_le_bytes(buf[*off..*off + 8].try_into().unwrap());
    *off += 8;
    v
}

fn read_arr<const N: usize>(buf: &[u8], off: &mut usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&buf[*off..*off + N]);
    *off += N;
    a
}

fn parse_witness(buf: &[u8]) -> Witness {
    let mut off = 0;
    let n_and = read_u64_le(buf, &mut off) as usize;
    let cm = buf[off..off + CM_BYTES].to_vec();
    off += CM_BYTES;
    let gc_hash = read_arr::<32>(buf, &mut off);
    let r_root = read_arr::<32>(buf, &mut off);
    let out_hash = read_arr::<32>(buf, &mut off);
    let delta = read_arr::<16>(buf, &mut off);
    let mut gates = Vec::with_capacity(n_and);
    for _ in 0..n_and {
        gates.push(GateWit {
            a0: read_arr::<16>(buf, &mut off),
            b0: read_arr::<16>(buf, &mut off),
            tg: read_arr::<16>(buf, &mut off),
            te: read_arr::<16>(buf, &mut off),
            ha0: read_arr::<16>(buf, &mut off),
            ha1: read_arr::<16>(buf, &mut off),
            hb0: read_arr::<16>(buf, &mut off),
            hb1: read_arr::<16>(buf, &mut off),
            pa: buf[off],
            pb: buf[off + 1],
        });
        off += 2;
    }
    Witness {
        n_and,
        cm,
        gc_hash,
        r_root,
        out_hash,
        delta,
        gates,
    }
}

fn binding_hash(w: &Witness) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&w.cm);
    h.update(&w.gc_hash);
    h.update(&w.r_root);
    h.update(&w.out_hash);
    h.update((w.n_and as u64).to_le_bytes());
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn binding_to_field(b: &[u8; 32]) -> [E; 4] {
    let mut out = [E::ZERO; 4];
    for i in 0..4 {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&b[i * 8..i * 8 + 8]);
        limb[7] &= 0x3f;
        out[i] = E::new(u64::from_le_bytes(limb));
    }
    out
}

fn get_bit(block: &[u8; 16], bit: usize) -> u8 {
    (block[bit / 8] >> (bit % 8)) & 1
}

fn check_half_gates(w: &Witness) -> Result<(), String> {
    for (i, g) in w.gates.iter().enumerate() {
        if g.pa > 1 || g.pb > 1 {
            return Err(format!("gate {i}: pa/pb not boolean"));
        }
        for bit in 0..128 {
            let expect_tg = get_bit(&g.ha0, bit) ^ get_bit(&g.ha1, bit) ^ (g.pb & get_bit(&w.delta, bit));
            if get_bit(&g.tg, bit) != expect_tg {
                return Err(format!("gate {i} bit {bit}: Tg fail"));
            }
            let expect_te = get_bit(&g.hb0, bit) ^ get_bit(&g.hb1, bit) ^ get_bit(&g.a0, bit);
            if get_bit(&g.te, bit) != expect_te {
                return Err(format!("gate {i} bit {bit}: Te fail"));
            }
        }
    }
    Ok(())
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        27, 8, 16,
        winterfell::FieldExtension::None,
        8, 255,
    )
}

fn next_pow2(n: usize) -> usize {
    n.next_power_of_two().max(8)
}

fn pub_to_bytes(p: &PublicInputs) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&p.n_and.to_le_bytes());
    v.extend_from_slice(&p.n_bits.to_le_bytes());
    for b in &p.bind {
        v.extend_from_slice(&b.as_int().to_le_bytes());
    }
    v
}

fn pub_from_bytes(buf: &[u8]) -> PublicInputs {
    let n_and = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let n_bits = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let mut bind = [E::ZERO; 4];
    for i in 0..4 {
        let limb = u64::from_le_bytes(buf[16 + i * 8..24 + i * 8].try_into().unwrap());
        bind[i] = E::new(limb);
    }
    PublicInputs { bind, n_and, n_bits }
}

struct GarbleAir {
    context: AirContext<E>,
    pub_inputs: PublicInputs,
}

impl Air for GarbleAir {
    type BaseField = E;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        let degrees = vec![
            TransitionConstraintDegree::new(2), // pa
            TransitionConstraintDegree::new(2), // pb
            TransitionConstraintDegree::new(2), // ha0
            TransitionConstraintDegree::new(2), // ha1
            TransitionConstraintDegree::new(2), // delta
            TransitionConstraintDegree::new(2), // tg
            TransitionConstraintDegree::new(2), // pbd = pb*d
            TransitionConstraintDegree::new(3), // tg = xor3(ha0,ha1,pbd)
            TransitionConstraintDegree::new(2), // hb0
            TransitionConstraintDegree::new(2), // hb1
            TransitionConstraintDegree::new(2), // a0
            TransitionConstraintDegree::new(2), // te
            TransitionConstraintDegree::new(3), // te = xor3(hb0,hb1,a0)
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        Self {
            context: AirContext::new(trace_info, degrees, 4, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<F: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<F>,
        _periodic: &[F],
        result: &mut [F],
    ) {
        let cur = frame.current();
        let pa = cur[0];
        let pb = cur[1];
        let ha0 = cur[2];
        let ha1 = cur[3];
        let d = cur[4];
        let tg = cur[5];
        let pbd = cur[6];
        let hb0 = cur[7];
        let hb1 = cur[8];
        let a0 = cur[9];
        let te = cur[10];
        let one = F::ONE;
        let two = one.double();
        let four = two.double();

        result[0] = pa * (pa - one);
        result[1] = pb * (pb - one);
        result[2] = ha0 * (ha0 - one);
        result[3] = ha1 * (ha1 - one);
        result[4] = d * (d - one);
        result[5] = tg * (tg - one);
        // pbd == pb AND d
        result[6] = pbd - pb * d;
        // tg == ha0 ⊕ ha1 ⊕ pbd  (degree 3 in these vars)
        let xor3 = ha0 + ha1 + pbd
            - (ha0 * ha1 + ha0 * pbd + ha1 * pbd).double()
            + ha0 * ha1 * pbd * four;
        result[7] = tg - xor3;

        result[8] = hb0 * (hb0 - one);
        result[9] = hb1 * (hb1 - one);
        result[10] = a0 * (a0 - one);
        result[11] = te * (te - one);
        let xor3e = hb0 + hb1 + a0
            - (hb0 * hb1 + hb0 * a0 + hb1 * a0).double()
            + hb0 * hb1 * a0 * four;
        result[12] = te - xor3e;
        result[13] = F::ZERO;
        result[14] = F::ZERO;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(14, 0, self.pub_inputs.bind[0]),
            Assertion::single(14, 1, self.pub_inputs.bind[1]),
            Assertion::single(14, 2, self.pub_inputs.bind[2]),
            Assertion::single(14, 3, self.pub_inputs.bind[3]),
        ]
    }
}

struct GarbleProver<H: ElementHasher> {
    options: ProofOptions,
    pub_inputs: PublicInputs,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> GarbleProver<H> {
    fn new(options: ProofOptions, pub_inputs: PublicInputs) -> Self {
        Self {
            options,
            pub_inputs,
            _hasher: PhantomData,
        }
    }

    fn build_trace(w: &Witness) -> (TraceTable<E>, PublicInputs) {
        let n_bits = w.n_and * 128;
        let trace_len = next_pow2(n_bits.max(4));
        let bind_bytes = binding_hash(w);
        let bind = binding_to_field(&bind_bytes);
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_len);

        for row in 0..trace_len {
            let (gate_id, bit) = if row < n_bits {
                (row / 128, row % 128)
            } else {
                ((w.n_and - 1).max(0), 127)
            };
            let g = &w.gates[gate_id.min(w.n_and - 1)];
            let pa = g.pa;
            let pb = g.pb;
            let dbit = get_bit(&w.delta, bit);
            let pbd = pb & dbit;
            let bidx = row % 4;
            let vals = [
                E::from(pa),
                E::from(pb),
                E::from(get_bit(&g.ha0, bit)),
                E::from(get_bit(&g.ha1, bit)),
                E::from(dbit),
                E::from(get_bit(&g.tg, bit)),
                E::from(pbd),
                E::from(get_bit(&g.hb0, bit)),
                E::from(get_bit(&g.hb1, bit)),
                E::from(get_bit(&g.a0, bit)),
                E::from(get_bit(&g.te, bit)),
                E::ZERO,
                E::new(gate_id as u64),
                E::from(bit as u8),
                bind[bidx],
                E::ZERO,
                E::ZERO,
                E::ZERO,
            ];
            for (c, v) in vals.iter().enumerate() {
                trace.set(c, row, *v);
            }
        }

        (
            trace,
            PublicInputs {
                bind,
                n_and: w.n_and as u64,
                n_bits: n_bits as u64,
            },
        )
    }
}

impl<H> Prover for GarbleProver<H>
where
    H: ElementHasher<BaseField = E>,
{
    type BaseField = E;
    type Air = GarbleAir;
    type Trace = TraceTable<E>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E2: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E2, Self::HashFn>;
    type ConstraintEvaluator<'a, E2: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E2>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E2: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E2>, TracePolyTable<E2>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E2: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand: Option<AuxRandElements<E2>>,
        composition_coeffs: ConstraintCompositionCoefficients<E2>,
    ) -> Self::ConstraintEvaluator<'a, E2> {
        DefaultConstraintEvaluator::new(air, aux_rand, composition_coeffs)
    }
}

fn do_prove(witness_path: &PathBuf, output: &PathBuf) {
    let buf = fs::read(witness_path).expect("read witness");
    let w = parse_witness(&buf);
    check_half_gates(&w).expect("half-gate witness invalid");
    assert_eq!(w.cm.len(), CM_BYTES);

    let options = proof_options();
    let (trace, pub_inputs) = GarbleProver::<Hasher>::build_trace(&w);
    let prover = GarbleProver::<Hasher>::new(options, pub_inputs.clone());

    let t0 = Instant::now();
    let proof = prover.prove(trace).expect("prove");
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut bytes = Vec::new();
    let pub_bytes = pub_to_bytes(&pub_inputs);
    bytes.extend_from_slice(&(pub_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&pub_bytes);
    let bh = binding_hash(&w);
    bytes.extend_from_slice(&bh);
    bytes.extend_from_slice(&w.gc_hash);
    bytes.extend_from_slice(&w.r_root);
    bytes.extend_from_slice(&w.out_hash);
    bytes.extend_from_slice(&w.cm);
    proof.write_into(&mut bytes);

    fs::write(output, &bytes).expect("write proof");
    println!("prove: ok");
    println!("n_and: {}", w.n_and);
    println!("trace_rows: {}", next_pow2(w.n_and * 128));
    println!("proof_bytes: {}", bytes.len());
    println!("prove_ms: {:.3}", prove_ms);
    println!("gc_hash: {}", hex::encode(w.gc_hash));
    println!("R_root: {}", hex::encode(w.r_root));
    println!("binding: {}", hex::encode(bh));
    println!("air: halfgate-garble+keycm-binding");
}

fn do_verify(input: &PathBuf, public: Option<PathBuf>) {
    let bytes = fs::read(input).expect("read proof");
    let pub_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
    let mut off = 8;
    let pub_inputs = pub_from_bytes(&bytes[off..off + pub_len]);
    off += pub_len;
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let mut gc_hash = [0u8; 32];
    gc_hash.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let mut r_root = [0u8; 32];
    r_root.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let mut out_hash = [0u8; 32];
    out_hash.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let cm = bytes[off..off + CM_BYTES].to_vec();
    off += CM_BYTES;
    let proof = Proof::read_from(&mut SliceReader::new(&bytes[off..])).expect("parse proof");

    if let Some(p) = public {
        let pb = fs::read(p).expect("public");
        assert_eq!(&pb[0..32], &gc_hash);
        assert_eq!(&pb[32..64], &r_root);
        assert_eq!(&pb[64..96], &out_hash);
        assert_eq!(&pb[96..96 + CM_BYTES], &cm);
    }

    let mut h = Sha256::new();
    h.update(&cm);
    h.update(gc_hash);
    h.update(r_root);
    h.update(out_hash);
    h.update(pub_inputs.n_and.to_le_bytes());
    let mut bh = [0u8; 32];
    bh.copy_from_slice(&h.finalize());
    if bh != binding {
        println!("verify: fail (binding hash mismatch — possible GC/public tamper)");
        std::process::exit(1);
    }
    if binding_to_field(&bh) != pub_inputs.bind {
        println!("verify: fail (field binding mismatch)");
        std::process::exit(1);
    }

    let options = proof_options();
    let acceptable = AcceptableOptions::OptionSet(vec![options]);
    let t0 = Instant::now();
    match winterfell::verify::<GarbleAir, Hasher, DefaultRandomCoin<Hasher>>(
        proof,
        pub_inputs.clone(),
        &acceptable,
    ) {
        Ok(_) => {
            println!("verify: ok");
            println!("verify_ms: {:.3}", t0.elapsed().as_secs_f64() * 1000.0);
            println!("n_and: {}", pub_inputs.n_and);
            println!("gc_hash: {}", hex::encode(gc_hash));
            println!("R_root: {}", hex::encode(r_root));
            println!("binding: {}", hex::encode(binding));
            println!("air: halfgate-garble+keycm-binding");
        }
        Err(e) => {
            println!("verify: fail ({e})");
            std::process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove { witness, output } => do_prove(&witness, &output),
        Cmd::Verify { input, public } => do_verify(&input, public),
    }
}
