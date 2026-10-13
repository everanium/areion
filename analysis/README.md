# P1 / P2 analysis

The SoEM22 construction in this library sums two Areion permutations: `P1` under the published round constants (Table 1) and `P2` under the second table of this library (Table 2). The security bound of Chen, Lambooij, and Mennink holds for two independent random permutations; treating `P1` and `P2` as independent is an assumption about this instantiation, not a proven property, and amounts to a related-key assumption on Areion with the round-constant table as the key (see [SoEM22](../README.md#soem22)).

No finite set of checks establishes that assumption. The checks below look for specific structure that would tie `P2` to `P1`, or that would let the sum `P1(u) ⊕ P2(u ⊕ δ)` be told apart from the sum of two independent permutations, each within a stated model. Every check that depends on the `P2` table covers both forms of its word 7 (RC7): **`pi`**, the library table (π word 22), and **`shift`**, the same table with Table 1's one-nibble shift applied to that word. Most checks run both forms in one pass; `values`, `integral`, and `hintegral` take one form per run (`--rc7p2`) and run `shift` as well wherever their rounds reach word 7, which first enters at round 8.

## Results

| Claim, within the stated model | `pi` | `shift` | Check |
|---|---|---|---|
| Related-constant differential characteristics `P1(u)` vs `P2(u ⊕ δ)`, every `δ` including 0: at least 155 / 154 active S-boxes over the 10 rounds of Areion-256, at least 240 over the 15 rounds of Areion-512 (thresholds for `2^(−2n/3)` at `2^−6` per S-box: 29 and 57) | holds | holds | `related`, `refined` |
| The byte-activity models (coarse and refined) admit every activity pattern observed on the reference rounds | holds | holds | `oracle` |
| **A.** No byte-structured linear symmetry of the constant-free round maps the `P1` constants onto the `P2` constants, for any pairing of rounds; no column rotation fixes the constants of either table | holds | holds | `symmetry`, `sbox` |
| **B1.** The S-box maps an affine subspace of dimension at least 2 onto an affine one only for the λ·F_4- and λ·F_16-lines, never onto itself | holds | holds | `sbox` |
| **B2.** Subspace trails valid for every coset (every key), from a difference in one byte or one bit: at most 2 rounds forward and 4 backward (Areion-256), 6 and 5 (Areion-512), independent of the constants | holds | holds | `subspace` |
| **B3.** No non-constant invariant in the setting of Beierle, Canteaut, Leander, and Rotella, for `P2` alone or common to `P1` and `P2` | holds | holds | `bclr` |
| **B4.** Weak cosets from byte-structured seeds: no exact coset trail past the first S-box layer fed by one-dimensional bytes mixed in a column; containment hulls below the generic bound `min(n, 2^d − 1)` for at most 3 / 6 rounds; the same maxima as a random table | holds | holds | `sbox`, `cosets` |
| **C.** Every output byte of `P1(u) ⊕ P2(u ⊕ δ)` can be inactive from 2 rounds on (byte model); with a random `δ`, every byte value occurs at rounds 2–4 (Areion-256) and 2–6 (Areion-512) | holds | holds | `impdiff`, `values` |
| **D.** Integral sums to order 5: the sum reaches as many rounds as one permutation, 3 rounds (Areion-256) and 5 rounds (Areion-512) | holds | holds | `integral`, `hintegral` |
| **F.** Byte-structured affine equivalence `P2 = B ∘ P1 ∘ A` reduces to column rotations with translations, which keep the related-constant bound at 238 or more (Areion-512) and at least 40 in the coarse model (Areion-256) | holds | holds | `affine`, `sbox`, `symmetry` |

### Related-constant bounds

`P1(u) ⊕ P2(u ⊕ δ)` behaves as a pair of trails whose difference receives `Δ_r = RC1_r ⊕ RC2_r` in every round; `Δ_r` is nonzero in all 16 bytes for both forms. In Areion-512 `Δ_r` is added to `y = SR ∘ SB(c)` with no MixColumns in between, so in every byte either `y` or `y ⊕ Δ_r` is active: 16 per round, 240 over 15 rounds, and the solver confirms that value is reached. In Areion-256 the coarse byte model gives 4 per round; the refined model determines exhaustively, per round and column, which activity patterns `MC(S) ⊕ Δ_r` can take, and gives:

| rounds | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| `pi` | 15 | 31 | 45 | 61 | 77 | 93 | 108 | 124 | 140 | 155 |
| `shift` | 15 | 31 | 45 | 61 | 77 | 93 | 108 | 123 | 139 | 154 |

The published RC7 of `P1` is π word 7 with a one-nibble shift. With the plain π word in its place (`--rc7p1 pi`), the refined Areion-256 bound is 153 for both forms of `P2` and the Areion-512 bound stays 240, so the conclusions do not depend on which form `P1` uses either.

`δ` ranges over every value, so every key difference `k1 ⊕ k2` of SoEM22 is covered. Equality up to a translation, `P2 = P1(· ⊕ a) ⊕ b`, would be a probability-1 related-constant differential; under the usual heuristic that a differential is not far stronger than its best characteristics, the bound excludes it. Round constants enter a linear trail only through its sign, so a linear relation between `P1`, `P2` and the input follows single-permutation mask trails in each permutation.

### A. Symmetries

A linear map `σ` that commutes with the constant-free round gives `P2 = σ ∘ P1 ∘ σ⁻¹` whenever `RC2_r = σ(RC1_r)` for every round, a relation no differential bound detects. The only GF(2)-linear byte map commuting with the AES S-box is the identity (by the classification of the linear self-equivalences of inversion, all 2040 candidates tested), and among the byte permutations that can commute with MixColumns, exactly the column rotations commute with the round; each was confirmed on the full permutations. No rotation maps any `P1` constant onto any `P2` constant (best agreement 2 of 16 bytes). As a control, a table built as `σ(RC1)` does yield `σ ∘ P1 ∘ σ⁻¹` on random Areion-512 inputs.

### B. Invariant subspaces and nonlinear invariants

- **B1.** Exhaustive over the affine subspaces of F_2^8. The cycles of the S-box (87, 81, 59, 27, 2) give it nonlinear invariants of its own, so the constants and linear layers have to block them.
- **B2.** The affine hull of every derivative image of the S-box and of its inverse is F_2^8, so for a subspace trail valid for every coset an S-box layer maps a difference space onto its projection outside the layer plus the full bytes on which it is nonzero, and linear steps map it exactly; the shared S-box layer of a round is applied once. Propagated this way from a difference in one byte or in one bit, at every position and start round, the difference space stays below the full state for at most 2 rounds forward and 4 backward in Areion-256, and 6 forward and 5 backward in Areion-512. Real differences of random pairs on the reference rounds always lie in the propagated spaces, and on sampled starts over the first four rounds their rank equals the propagated dimension, so the propagation is not looser than the cipher. The round constants play no part.
- **B3.** Areion is written as alternating partial S-box layers and affine maps on the full state (Areion-256 needs an inverse S-box layer for this), checked against the library. The smallest subspace `W` containing the constant differences and invariant under every linear part is the whole state for `P1` and `P2` together; where it is smaller for one permutation alone, every point of the quotient joins one class under the S-box layers, so only constant invariants remain. A table repeating one constant gives `dim W = 0`.
- **B4.** Exhaustive over linear parts, so offsets, keys, and constants do not change the outcome: no λ·F_4- or λ·F_16-line is mapped by the S-box (or by the linear part of its affine map) onto a λ·F_4- or λ·F_16-line or a coset of one, and no direction tuple of 2 to 4 one-dimensional bytes gathered into a column passes all four MixColumns rows (16,581,375 tuples for four bytes). Coset trails on the reference rounds, from one full byte, one byte over each line, one-dimensional bytes in a column or a diagonal, and the fixed spaces of the column rotations: exact for at most 2 rounds (Areion-256) / 3 (Areion-512), including runs that reach the last round, hulls below the generic bound `min(n, 2^d − 1)` (an upper bound for every permutation on a `d`-dimensional input, reached by a random one) for at most 3 / 6 rounds, the same overall maxima for `P1`, both `P2` forms, and a random table. When the input coset has dimension above 16, the image hull is computed from sampled points; a sampled hull lies inside the true one, so a full hull is a proof, and an underestimate can only lengthen the reported runs, which keeps the maxima upper bounds. Every seed has its own seeded generator, so runs repeat exactly. With constants invariant under a column rotation the matching fixed space stays an exact invariant subspace through every round, and the engine reports it.

Arbitrary cosets are not searched: any permutation maps about `2^(2n)` small cosets onto cosets by chance, so such a search has no finite target.

### C. Impossible differentials and byte values

In the related-constant byte model every output byte of `P1(u) ⊕ P2(u ⊕ δ)` can be inactive from round 2 on, for `δ` free and for `δ` fully active, up to full rounds. On the reference rounds, with a random `δ`, every byte value appears in a `2^24`-sample histogram at rounds 2 to 4 (Areion-256) and 2 to 6 (Areion-512), and the largest χ² over the bytes stays within the range expected for uniform bytes (at most 304.2 over 32 bytes and 323.7 over 64 bytes; χ²(255) has mean 255 and standard deviation about 22.6); each byte is zero about once in 256 (`2^20` samples) at rounds 2, 3, and full rounds, for both forms. For one permutation, the impossible differentials that the standard constant-independent models derive are the same for `P1` and `P2`.

### D. Integral properties

Round constants do not enter integral propagation, and the XOR of two balanced sums is balanced. Λ-sets of order 1 to 5 (up to `2^40` texts; orders 4 and 5 with AES-NI) balance output bytes of `P1(u) ⊕ P2(u ⊕ δ)` over the same rounds as for `P1` alone: up to 3 rounds of Areion-256 and 5 rounds of Areion-512, chance-level beyond, in line with the integral evaluation of the Areion paper.

### E. Known attacks on SoEM variants

Chen, Lambooij, and Mennink give birthday-bound attacks when the two permutations are identical (SoEM1) or the two keys are identical (SoEM21). Two different tables exclude the first case exactly; its approximate forms, equality up to a translation or up to a structural symmetry, are covered above. The second case is a property of how the keys are drawn; its input difference `δ = 0` is included in the related-constant bounds and the impossible-differential model, and the byte-value histograms run it as well: there Areion-512 keeps some output bytes constant for up to 3 rounds and Areion-256 for 1 round, until the constant difference has reached every block, and the bytes are uniform at that sample size from the next round on.

### F. Affine equivalence

Through an S-box layer followed by MixColumns, the only byte-wise affine map that survives is the identity (all 2040 linear self-equivalences of inversion tested), so a byte-structured equivalence is a byte permutation. A byte permutation `p` applied before an S-box layer and ShiftRows reappears after them as `T(p) = SR ∘ p ∘ SR⁻¹`, so the map may differ from round to round; following the round structure, the map on the F-function input has to satisfy `T³(p) = p` in Areion-256 and `T(p) = p` in Areion-512, with every `T^i(p)` commuting with MixColumns. Of the 6144 candidates exactly the column rotations of section A satisfy either condition (`symmetry`), so per-round maps add nothing. A rotation combined with translations is a related-constant case with `Δ_r = RC1_r ⊕ σ⁻¹(RC2_r)`, which has one zero byte in two of the 15 rounds: 238 for Areion-512 (237 with `--rc7p1 pi` for the `P2` `pi` form, where one rotation gains a third zero byte), and 40 to 44 in the coarse Areion-256 model (45 for one rotation of the `pi` form with `--rc7p1 pi`). No component function of the S-box has a linear structure, the usual condition under which an affine map carrying an S-box layer onto an S-box layer respects the bytes; that step is an argument from the literature, not a proof given here.

### G. Clustering

The bounds are on characteristics. Within one round there is no clustering: the round's input and output differences fix every S-box layer's output difference, so a one-round differential has exactly one characteristic, and clustering can only come from summing over the differences between rounds. At `2^−6` per S-box the related-constant bounds give `2^−930` (Areion-256, `pi`; `2^−924` for `shift`) and `2^−1440` (Areion-512) against `2^−171` and `2^−341`: a differential would have to gather about `2^759` (`2^753`) and `2^1099` times the weight of the best characteristic. That is a margin, not a bound on differentials.

### Open

- Affine equivalences that are not byte-structured: the reduction to bytes in section F rests on the literature, and equivalences that do not carry S-box layers onto S-box layers are not covered.
- Weak cosets beyond the byte-structured seeds: byte mixes other than one-dimensional bytes in a column are sampled, not exhausted, and arbitrary cosets give no finite search.
- Impossible differentials beyond the byte-level models, for one permutation or between `P1` and `P2`.
- Bounds on differentials rather than characteristics. Linear relations between `P1` and `P2` are argued from the single-permutation case and not quantified here; boomerang-type relations are not examined.
- Integral properties above order 5, including the paper's distinguishers with nearly every byte active.
- The independence of `P1` and `P2` itself.

## Reproducing

### Dependencies

Go at the version in `go.mod` (an older Go, 1.21 or later, fetches it when `GOTOOLCHAIN=auto`), Python 3.9 or later with `python-sat`, and for `hintegral` a C compiler, `make`, and an x86-64 CPU with AES-NI. Tested in containers of the distributions below.

Arch Linux:

```
pacman -S --needed go python gcc make
```

Debian 13:

```
apt-get install golang-go python3 python3-venv gcc make ca-certificates
```

Rocky Linux 9 and other RHEL 9 derivatives (their Go defaults to `GOTOOLCHAIN=local`, which refuses the newer version `go.mod` asks for):

```
dnf install golang python3 python3-pip gcc make
export GOTOOLCHAIN=auto
```

Then, from the module root:

```
python3 -m venv .venv && . .venv/bin/activate
pip install python-sat
```

### Running

```
python3 analysis/run.py list                      # checks with expected run times
python3 analysis/run.py all --quick               # every check, reduced; a few minutes
python3 analysis/run.py <check> [--quick] [--record] [--rc7p1 shift|pi] [--rc7p2 pi|shift]
python3 analysis/run.py clean                     # remove analysis/build
```

Run from the module root, inside the virtual environment. The Go program and the C program are rebuilt on every run (both builds are incremental), and the feasibility tables are rebuilt whenever the Go sources change. Generated files (the constant tables as JSON, sample input / output lines of the library permutations, column feasibility tables, traces, the Go and C binaries, and the C constants header) go to `analysis/build`. `--record` writes the output to `analysis/results/<check>.txt` (with `_quick`, `_rc7p2-shift` or `_rc7p1-pi` added for those options), headed by the command; the files there are the reference outputs of full runs. Run times in `list` are for a 16-core desktop.

`--rc7p2` selects the `P2` form for the checks that run one table. `--rc7p1 pi` replaces word 7 of `P1` by the plain π word 7 (the published table applies a one-nibble shift) in every check except `ref`, and never in the comparisons with the library, for comparison.

`results/*_rc7p1-pi.txt` hold such runs of `oracle`, `related`, `refined`, `symmetry`, `bclr`, and `affine`. The refined Areion-256 bound becomes 153 for both `P2` forms; for the `P2` `pi` form the Areion-512 bound of section F becomes 237 and one coarse Areion-256 rotation bound becomes 45. None of those conclusions changes.

The Go program in `analysis/go` carries a copy of the library's purego rounds and constant tables, so that it can run reduced rounds and the `shift` table; its test pins that copy to the exported permutations.

| Directory | Contents |
|---|---|
| `go/` | reference rounds, oracle, feasibility tables, symmetry search, coset engine, empirical checks |
| `py/` | byte-activity models (pysat) and the algebraic checks |
| `c/` | AES-NI program for integral sums of order 4 and 5 |
| `results/` | reference outputs |
