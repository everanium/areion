# P1 / P2 analysis

The SoEM22 construction in this library sums two Areion permutations: `P1` under the published round constants (Table 1) and `P2` under the second table of this library (Table 2). The security bound of Chen, Lambooij, and Mennink holds for two independent random permutations; treating `P1` and `P2` as independent is an assumption about this instantiation, not a proven property, and amounts to a related-key assumption on Areion with the round-constant table as the key (see [SoEM22](../README.md#soem22)).

No finite set of checks establishes that assumption. The checks below look for specific structure that would tie `P2` to `P1`, or that would let the sum `P1(u) ⊕ P2(u ⊕ δ)` be told apart from the sum of two independent permutations, each within a stated model. `P2` is the library table, whose word 7 (RC7) takes the one-nibble shift that RC7 of `P1` has in Table 1. The shift form follows Table 1, in agreement with the Areion authors, and is not a security choice: the checks that depend on `P2` also cover the plain π word 22 in that position (`pi`, in the same pass or with `--rc7p2 pi`), every claim below holds for both forms, and the only bound that differs is the refined related-constant bound of Areion-256, by one active S-box (154 against 155 over 10 rounds).

## Results

| Claim, within the stated model | Result | Check |
|---|---|---|
| Related-constant differential characteristics `P1(u)` vs `P2(u ⊕ δ)`, every `δ` including 0: at least 154 active S-boxes over the 10 rounds of Areion-256, at least 240 over the 15 rounds of Areion-512 (thresholds for `2^(−2n/3)` at `2^−6` per S-box, a heuristic conversion, see section G: 29 and 57) | holds | `related`, `refined` |
| The byte-activity models (coarse and refined) admit every activity pattern observed on the reference rounds | holds | `oracle` |
| **A.** No byte-structured linear symmetry of the constant-free round maps the `P1` constants onto the `P2` constants, for any pairing of rounds; no column rotation fixes the constants of either table | holds | `symmetry`, `sbox` |
| **B1.** The S-box maps an affine subspace of dimension at least 2 onto an affine one only for the λ·F_4- and λ·F_16-lines, never onto itself | holds | `sbox` |
| **B2.** Subspace trails valid for every coset (every key), from a difference in one byte or one bit: at most 2 rounds forward and 4 backward (Areion-256), 6 and 5 (Areion-512), independent of the constants | holds | `subspace` |
| **B3.** No non-constant invariant in the setting of Beierle, Canteaut, Leander, and Rotella, for `P2` alone or common to `P1` and `P2` | holds | `bclr` |
| **B4.** Weak cosets from byte-structured seeds: no exact coset trail past the first S-box layer fed by one-dimensional bytes mixed in a column; containment hulls below the generic bound `min(n, 2^d − 1)` for at most 3 / 6 rounds; the same maxima as a random table | holds | `sbox`, `cosets` |
| **C.** Every output byte of `P1(u) ⊕ P2(u ⊕ δ)` can be inactive from 2 rounds on (byte model); with a random `δ`, every byte value occurs at rounds 2–4 (Areion-256) and 2–6 (Areion-512) | holds | `impdiff`, `values` |
| **D.** Integral sums to order 5: the sum reaches as many rounds as one permutation, 3 rounds (Areion-256) and 5 rounds (Areion-512) | holds | `integral`, `hintegral` |
| **F.** Byte-structured affine equivalence `P2 = B ∘ P1 ∘ A` reduces to column rotations with translations, which keep the related-constant bound at 238 or more (Areion-512) and at least 40 in the coarse model (Areion-256) | holds | `affine`, `sbox`, `symmetry` |
| **H.** Linear trails, one set of trail bounds for `P1` and `P2`: at least 65 active S-boxes over the 10 rounds of Areion-256 and at least 101 over the 15 rounds of Areion-512, at least twice that for a term of a linear approximation of `P1(u) ⊕ P2(u ⊕ δ)` (thresholds for `2^(2n/3)` known inputs at `2^−3` per S-box, a heuristic conversion, see section H: 15 and 29 per permutation); for Areion-512 with the S-box chain of `F3` at its exact maximum, at least 164 bits per permutation (threshold 86) | holds | `linear`, `weighted` |
| **I.** Boomerang estimates under the four assignments of the two tables, with up to two free middle rounds: below `2^(−2n/3)` at the full number of rounds; the largest estimate is `2^−480` for Areion-256, and `2^−490` for Areion-512 with the S-box chain of `F3` at its exact maximum (`2^−504` under the product rule; a heuristic estimate, resting partly on window lower bounds, see section I) | holds | `boomerang`, `weighted` |

### Related-constant bounds

`P1(u) ⊕ P2(u ⊕ δ)` behaves as a pair of trails whose difference receives `Δ_r = RC1_r ⊕ RC2_r` in every round; `Δ_r` is nonzero in all 16 bytes. In Areion-512 `Δ_r` is added to `y = SR ∘ SB(c)` with no MixColumns in between, so in every byte either `y` or `y ⊕ Δ_r` is active: 16 per round, 240 over 15 rounds, and the solver confirms that value is reached. In Areion-256 the coarse byte model gives 4 per round; the refined model determines exhaustively, per round and column, which activity patterns `MC(S) ⊕ Δ_r` can take, and gives:

| rounds | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| Areion-256 | 15 | 31 | 45 | 61 | 77 | 93 | 108 | 123 | 139 | 154 |

The published RC7 of `P1` is π word 7 with a one-nibble shift. With the plain π word in its place (`--rc7p1 pi`), the refined Areion-256 bound is 153 and the Areion-512 bound stays 240, so the conclusions do not depend on which form `P1` uses either.

`δ` ranges over every value, so every key difference `k1 ⊕ k2` of SoEM22 is covered. Equality up to a translation, `P2 = P1(· ⊕ a) ⊕ b`, would be a probability-1 related-constant differential; under the usual heuristic that a differential is not far stronger than its best characteristics, the bound excludes it. Round constants enter a linear trail only through its sign, so a linear relation between `P1`, `P2` and the input follows single-permutation mask trails in each permutation (section H).

### A. Symmetries

A linear map `σ` that commutes with the constant-free round gives `P2 = σ ∘ P1 ∘ σ⁻¹` whenever `RC2_r = σ(RC1_r)` for every round, a relation no differential bound detects. The only GF(2)-linear byte map commuting with the AES S-box is the identity (by the classification of the linear self-equivalences of inversion, all 2040 candidates tested), and among the byte permutations that can commute with MixColumns, exactly the column rotations commute with the round; each was confirmed on the full permutations. No rotation maps any `P1` constant onto any `P2` constant (best agreement 2 of 16 bytes). As a control, a table built as `σ(RC1)` does yield `σ ∘ P1 ∘ σ⁻¹` on random Areion-512 inputs.

### B. Invariant subspaces and nonlinear invariants

- **B1.** Exhaustive over the affine subspaces of F_2^8. The cycles of the S-box (87, 81, 59, 27, 2) give it nonlinear invariants of its own, so the constants and linear layers have to block them.
- **B2.** The affine hull of every derivative image of the S-box and of its inverse is F_2^8, so for a subspace trail valid for every coset an S-box layer maps a difference space onto its projection outside the layer plus the full bytes on which it is nonzero, and linear steps map it exactly; the shared S-box layer of a round is applied once. Propagated this way from a difference in one byte or in one bit, at every position and start round, the difference space stays below the full state for at most 2 rounds forward and 4 backward in Areion-256, and 6 forward and 5 backward in Areion-512. Real differences of random pairs on the reference rounds always lie in the propagated spaces, and on sampled starts over the first four rounds their rank equals the propagated dimension, so the propagation is not looser than the cipher. The round constants play no part.
- **B3.** Areion is written as alternating partial S-box layers and affine maps on the full state (Areion-256 needs an inverse S-box layer for this), checked against the library. The smallest subspace `W` containing the constant differences and invariant under every linear part is the whole state for `P1` and `P2` together; where it is smaller for one permutation alone, every point of the quotient joins one class under the S-box layers, so only constant invariants remain. A table repeating one constant gives `dim W = 0`.
- **B4.** Exhaustive over linear parts, so offsets, keys, and constants do not change the outcome: no λ·F_4- or λ·F_16-line is mapped by the S-box (or by the linear part of its affine map) onto a λ·F_4- or λ·F_16-line or a coset of one, and no direction tuple of 2 to 4 one-dimensional bytes gathered into a column passes all four MixColumns rows (16,581,375 tuples for four bytes). Coset trails on the reference rounds, from one full byte, one byte over each line, one-dimensional bytes in a column or a diagonal, and the fixed spaces of the column rotations: exact for at most 2 rounds (Areion-256) / 3 (Areion-512), including runs that reach the last round, hulls below the generic bound `min(n, 2^d − 1)` (an upper bound for every permutation on a `d`-dimensional input, reached by a random one) for at most 3 / 6 rounds, the same overall maxima for `P1`, both `P2` forms, and a random table. When the input coset has dimension above 16, the image hull is computed from sampled points; a sampled hull lies inside the true one, so a full hull is a proof, and an underestimate can only lengthen the reported runs, which keeps the maxima upper bounds. Every seed has its own seeded generator, so runs repeat exactly. With constants invariant under a column rotation the matching fixed space stays an exact invariant subspace through every round, and the engine reports it.

Arbitrary cosets are not searched: any permutation maps about `2^(2n)` small cosets onto cosets by chance, so such a search has no finite target.

### C. Impossible differentials and byte values

In the related-constant byte model every output byte of `P1(u) ⊕ P2(u ⊕ δ)` can be inactive from round 2 on, for `δ` free and for `δ` fully active, up to full rounds. On the reference rounds, with a random `δ`, every byte value appears in a `2^24`-sample histogram at rounds 2 to 4 (Areion-256) and 2 to 6 (Areion-512), and the largest χ² over the bytes stays within the range expected for uniform bytes (at most 304.2 over 32 bytes and 323.7 over 64 bytes; χ²(255) has mean 255 and standard deviation about 22.6); each byte is zero about once in 256 (`2^20` samples) at rounds 2, 3, and full rounds. For one permutation, the impossible differentials that the standard constant-independent models derive are the same for `P1` and `P2`.

### D. Integral properties

Round constants do not enter integral propagation, and the XOR of two balanced sums is balanced. Λ-sets of order 1 to 5 (up to `2^40` texts; orders 4 and 5 with AES-NI) balance output bytes of `P1(u) ⊕ P2(u ⊕ δ)` over the same rounds as for `P1` alone: up to 3 rounds of Areion-256 and 5 rounds of Areion-512, chance-level beyond, in line with the integral evaluation of the Areion paper. `hintegral` also runs 8 rounds of Areion-512 at order 4 with both `P2` forms; the counts are identical.

### E. Known attacks on SoEM variants

Chen, Lambooij, and Mennink give birthday-bound attacks when the two permutations are identical (SoEM1) or the two keys are identical (SoEM21). Two different tables exclude the first case exactly; its approximate forms, equality up to a translation or up to a structural symmetry, are covered above. The second case is a property of how the keys are drawn; its input difference `δ = 0` is included in the related-constant bounds and the impossible-differential model, and the byte-value histograms run it as well: there Areion-512 keeps some output bytes constant for up to 3 rounds and Areion-256 for 1 round, until the constant difference has reached every block, and the bytes are uniform at that sample size from the next round on.

### F. Affine equivalence

Through an S-box layer followed by MixColumns, the only byte-wise affine map that survives is the identity (all 2040 linear self-equivalences of inversion tested), so a byte-structured equivalence is a byte permutation. A byte permutation `p` applied before an S-box layer and ShiftRows reappears after them as `T(p) = SR ∘ p ∘ SR⁻¹`, so the map may differ from round to round; following the round structure, the map on the F-function input has to satisfy `T³(p) = p` in Areion-256 and `T(p) = p` in Areion-512, with every `T^i(p)` commuting with MixColumns. Of the 6144 candidates exactly the column rotations of section A satisfy either condition (`symmetry`), so per-round maps add nothing. A rotation combined with translations is a related-constant case with `Δ_r = RC1_r ⊕ σ⁻¹(RC2_r)`, which has one zero byte in two of the 15 rounds: 238 for Areion-512, and 40 to 44 in the coarse Areion-256 model. No component function of the S-box has a linear structure, the usual condition under which an affine map carrying an S-box layer onto an S-box layer respects the bytes; that step is an argument from the literature, not a proof given here.

### G. From active S-boxes to probabilities

The bounds count active S-boxes. Turning a count into a probability with `2^−6` per active S-box is the usual product rule, which assumes independent S-box transitions; Denis ([ePrint 2026/1935](https://eprint.iacr.org/2026/1935)) shows that for Areion it is not an upper bound. Two S-boxes in series on one byte, `S(S(x) ⊕ k)` in `F3,r(x) = F0(F1(x) ⊕ k_r)` of Areion-512 (the note's notation, with `F1 = SR ∘ SB` and `F0 = MC ∘ F1`), give `2^−7` jointly where the product of the two transitions, `2^−7` each, gives `2^−14` (sections H and I charge that chain by its exact maximum), and the coupled bytes of one Areion-256 column give a two-round differential of probability `2^−31` where the product gives `2^−34`. The same note, and Taiyama et al. (Computer Security Symposium 2023) before it, observe that an S-box layer shared by two functions imposes one condition, which the models here respect by counting it once.

Within one round there is no clustering: the round's input and output differences fix every S-box layer's output difference, so a one-round differential has exactly one characteristic, and clustering can only come from summing over the differences between rounds. Under the product rule the related-constant bounds give `2^−924` (Areion-256) and `2^−1440` (Areion-512) against `2^−171` and `2^−341`: about `2^753` and `2^1099` apart. These are margins of a heuristic estimate, not bounds: they show how far the estimate is from the threshold, and they stay large under corrections of the size reported by Denis.

### H. Linear trails

A linear approximation follows a mask trail. Round constants leave the masks unchanged and only set the sign of a trail's correlation, so one set of trail bounds holds for `P1` and for `P2`; the correlation of a linear hull, a signed sum over trails, does depend on the table. The model (`py/linear.py`) is the dual of the difference model: an XOR forces equal masks on its two inputs and its output, a value read twice takes the XOR of the two branch masks, and the S-box layer shared by two functions is active where that XOR is nonzero and is counted once. Like the difference models it tracks byte activity only, so its minima are lower bounds on the number of active S-boxes of actual trails. Minimum numbers of active S-boxes over `r` rounds:

| rounds | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| Areion-256 | 1 | 5 | 10 | 21 | 30 | 35 | 40 | 54 | 60 | 65 |
| Areion-512 | 0 | 2 | 6 | 11 | 24 | 31 | 44 | 57 | 64 | 72 |

The Areion-512 row is computed with SAT to 8 rounds and with the MILP solver HiGHS to 10 rounds (see the end of this section). Splitting 15 rounds into windows of those lengths gives at least 101 active S-boxes.

A linear approximation of SoEM22, `α · m ⊕ β · F(m)`, has, up to a sign set by the keys, the correlation of `α · u ⊕ β · (P1(u) ⊕ P2(u ⊕ δ))` with `δ = k1 ⊕ k2`. That correlation is a sum, over the ways of writing `α` as the XOR of two nonzero input masks, of the product of a `P1` correlation and a `P2` correlation with the same output mask `β`; each of those is a hull, a sum over mask trails, and a term made of one trail through each permutation carries at least twice the single-permutation count. With `2^−3` per active S-box (the largest absolute correlation of the AES S-box), no such term exceeds `2^−390` for Areion-256 (2 × 65 active S-boxes over 10 rounds), against `2^−85`, about the smallest correlation detectable with the `2^171` (`2^(2n/3)`) known inputs up to which the SoEM22 bound holds (`2^−171` for Areion-512, with `2^341`). The sum over the splits of `α` and over the hulls is not bounded here; for two independent permutations it is generically of order `2^(−n/2)`, which needs about `2^n` known inputs, more than `2^(2n/3)`. The caveats of section G apply in the same way: the per-S-box rule is a heuristic. Relations with different output masks, `β1 · P1(u) ⊕ β2 · P2(u ⊕ δ)`, are relations of the pair but not approximations of SoEM22, and are not examined.

For Areion-512 the per-S-box rule fails in one place. In `F3`, a byte passes through two S-boxes with nothing between them but a round-constant byte, `S(S(x) ⊕ k)`, and the output of the first also feeds `F0` of the same word; everywhere else in Areion a byte passes from one S-box to the next through MixColumns or through an XOR with another word of the state. Summed over the mask between its two S-boxes, the chain reaches correlation 11/32 (Denis, section 4.1), and 3/8, about `2^−1.42`, with the branch into `F0`, at its maximum over the constant bytes (`go run ./analysis/go chain`), where the rule gives `2^−6` for its two S-boxes. Charging every counted S-box at that rate, about 0.71 bits each, would leave about 71.5 bits per permutation over 15 rounds and terms up to about `2^−143`, above `2^−171`. That worst case does not occur: the weighted model (`py/wmodel.py`, `py/weighted.py`, check `weighted`) charges each chain by its exact maximum, rounded down to whole bits (1 bit with both S-boxes active, 3 bits with one, and 3 bits for an S-box of the word `a`), and its minima over 1 to 8 rounds are 0, 1, 7, 23, 36, 48, 70 and 94 bits. Windows of those lengths give at least 164 bits per permutation over 15 rounds, so no term exceeds `2^−328`, against `2^−171`. Areion-256 has no such chain: its round constant sits between the two halves of `F2`, with MixColumns in between, and the coupling of the bytes of one column there (section G) is not modelled.

The search (`py/bounds.py`) adds window conditions: if `B(w)` is the minimum over `w` rounds, every `w` consecutive rounds of a longer trail carry at least `B(w)` active S-boxes, since the model's constraints are local to a round and every round is the same function up to renaming the words. It finds a trail and demands fewer active S-boxes until that is unsatisfiable. `bounds.py --jobs` can also split the last proof into cubes by the exact number of active S-boxes in one round, which together cover every trail, while a single solver keeps descending beside them; on the Areion-512 cells of 5 and 6 rounds that saves little or nothing, so `run.py --jobs` spends the processes on several round counts at once instead. `linear` first checks that the three search paths (without windows, with windows, on cubes alone) give the same minimum on five rounds of Areion-512.

The Areion-512 linear and single-permutation minima of sections H and I, weighted or not, are those of the MILP solver HiGHS (`py/milp.py`, `run.py --solver highs`); the related-constant bounds come from the SAT search alone. It solves the same model, with the branch number of each MixColumns column and each window condition written as linear rows in place of their clauses; on every round count the SAT search reaches, both solvers give the same minima (`solvers`). Neither solver emits a checkable proof, and HiGHS works in floating point with tolerances; a minimum is accepted only when its objective is an integer and its dual bound rounds up to it. Its minima also serve as windows for longer round counts, so an error in one would carry over to the longer ones.

### I. Boomerang estimates

A boomerang distinguisher combines two short differentials, a top one over `r1` rounds and a bottom one over `r2`, and queries the permutations in both directions. SoEM22 offers neither inverse queries nor the two permutations separately, so the estimates concern the pair `(P1, P2)` as public permutations, the setting in which their independence is assumed. The only keys are the two constant tables, so in each half the two pairs run either under one table (table difference 0, a single-permutation differential) or `P1` against `P2` (table difference `Δ`, the related-constant model above). `boomerang` evaluates the four assignments; single / single is the ordinary boomerang on one permutation, the reference case. The estimate is `2^(−12 · (B_top(r1) + B_bot(r2)))`, the product rule of section G over the two pairs of each half, maximised over the splits. Like the product rule it is neither an upper nor a lower bound: it leaves out both the gain of the switch between the halves and incompatibilities between them. Three variants:

- strict: `r1 + r2 = R`;
- one free middle round: `r1 + r2 = R − 1`. A round of Areion is exactly free for a quartet when the four texts agree on the words that feed its S-boxes, in every assignment of the tables, since the differences the constants induce cancel in pairs; with one side active there, it is free when the pairs of the other side run under one table. This is an argument from the round structure, not a check run by `run.py`;
- two free middle rounds: `r1 + r2 = R − 2`, a sensitivity check. Middles of two or more rounds are not free in the related settings, but they replace the per-pair charges of the trail model by second-order conditions on the S-box; these are not quantified here.

Single-permutation bounds come from the difference model with a nonzero input difference (`bounds.py single`); related-constant halves come from the coarse model, and for Areion-256 also from the refined model per round, since the bottom half starts in the middle of the permutation. Where a table does not reach a length, the window lower bound takes its place (marked `*`), which can only raise the estimate. An estimate of `2^−0` means that the model gives no bound for that split, not that a quartet is known.

Estimates at the full number of rounds, strict / one free round / two free rounds (Areion-256 with the refined related-constant halves, `shift` form):

| top / bottom | Areion-256, 10 rounds | Areion-512, 15 rounds |
|---|---|---|
| single / single (reference) | `2^−600` / `2^−540` / `2^−480` | `2^−552*` / `2^−528*` / `2^−504*` |
| single / related | `2^−900` / `2^−840` / `2^−660` | `2^−1056*` / `2^−876*` / `2^−780*` |
| related / single | `2^−900` / `2^−840` / `2^−660` | `2^−1056*` / `2^−876*` / `2^−780*` |
| related / related | `2^−1848` / `2^−1656` / `2^−1464` | `2^−2880*` / `2^−2688*` / `2^−2496*` |

Against the threshold of section G, `2^(−2n/3)` (`2^−171` and `2^−341`), every estimate at the full number of rounds is lower, in every assignment and variant. A boomerang of probability `p` needs about `1/p` quartets, so none of these estimates gives a distinguisher of the pair with fewer queries than the `2^(2n/3)` up to which the SoEM22 bound holds, and none contradicts the independence assumption that bound rests on. In Areion-256 the estimates of the three assignments that mix the tables fall below the threshold from 4 rounds on in every variant, and those of the reference case from 5 (strict), 6 (one free round), and 7 rounds (two free rounds). In Areion-512 the single-permutation table is computed to 7 rounds, so the estimates marked `*` rest on window lower bounds and can only fall as the table grows; with them the mixed assignments fall below the threshold from 8 rounds on in every variant, the reference case from 11 (strict), 12, and 13 rounds. These are estimates under the product rule with the caveats of section G and the switch caveats above, not bounds on boomerang probabilities.

In Areion-512 the single-permutation halves pass through the S-box chain of `F3` (section H). A transition of the pair of its S-boxes has probability at most `2^−7`, for every constant byte and nonzero input difference (Denis, section 3.2), where the product rule gives `2^−12`; between `P1` and `P2` (constant bytes `k1 ≠ k2`) it is at most `2^−6`, that of one S-box, and since `Δ_r` is nonzero in every byte, every chain of a related half has an active S-box, so the related halves keep 96 bits per round. Charging every S-box of the reference case at the rate of the pair would raise its estimate at 15 rounds from `2^−504` to about `2^−294`, above the threshold. That worst case does not occur either: with the weighted single-permutation minima over 1 to 10 rounds, 0, 6, 13, 20, 48, 96, 166, 197, 238 and 283 bits, the estimates at 15 rounds are `2^−604*` / `2^−572` / `2^−490` for single / single, `2^−856*` / `2^−784*` / `2^−770*` for single / related and related / single, and unchanged for related / related, all below `2^−341` (check `weighted`).

### Open

- Affine equivalences that are not byte-structured: the reduction to bytes in section F rests on the literature, and equivalences that do not carry S-box layers onto S-box layers are not covered.
- Weak cosets beyond the byte-structured seeds: byte mixes other than one-dimensional bytes in a column are sampled, not exhausted, and arbitrary cosets give no finite search.
- Impossible differentials beyond the byte-level models, for one permutation or between `P1` and `P2`.
- Bounds on probabilities: the conversion from active S-boxes is heuristic (sections G, H, I), differentials and linear hulls can collect several trails, and the boomerang estimates leave out the gain and the incompatibilities of the switch between the halves (section I).
- Linear trails of Areion-512 beyond 10 rounds and single-permutation differential trails beyond 7 (unweighted) or 10 rounds (weighted): only window lower bounds here.
- Integral properties above order 5, including the paper's distinguishers with nearly every byte active.
- The independence of `P1` and `P2` itself.

## Reproducing

### Dependencies

Go at the version in `go.mod` (an older Go, 1.21 or later, fetches it when `GOTOOLCHAIN=auto`), Python 3.9 or later with `python-sat` (and `highspy` for `--solver highs`), and for `hintegral` a C compiler, `make`, and an x86-64 CPU with AES-NI. Tested in containers of the distributions below.

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
pip install python-sat highspy
```

### Running

```
python3 analysis/run.py list                               # checks with expected run times
python3 analysis/run.py all --quick                        # every check, reduced; a few minutes
python3 analysis/run.py <check> [--quick] [--record] [--rc7p1 shift|pi] [--rc7p2 shift|pi]
python3 analysis/run.py linear --rounds 7                  # SAT tables of section H; about 5 h
python3 analysis/run.py boomerang --rounds 7               # tables and estimates of section I; about 2 h
python3 analysis/run.py linear --rounds 10 --solver highs  # Areion-512 of section H to 10 rounds; about 1 h
python3 analysis/run.py weighted --rounds 10 --linear-rounds 8 --solver highs  # weighted bounds of sections H and I; about 20 h
python3 analysis/run.py linear|boomerang|weighted [--jobs N] [--rounds R] [--record]
python3 analysis/run.py solvers                            # SAT round counts again, with HiGHS alone
python3 analysis/run.py clean                              # remove analysis/build
```

Run from the module root, inside the virtual environment. The Go program and the C program are rebuilt on every run (both builds are incremental), and the feasibility tables are rebuilt whenever the Go sources change. Generated files (the constant tables as JSON, sample input / output lines of the library permutations, column feasibility tables, traces, the Go and C binaries, and the C constants header) go to `analysis/build`. `--record` writes the output to `analysis/results/<check>.txt` (with `_quick`, `_rc7p2-pi`, `_rc7p1-pi` or `_highs` added for those options), headed by the command; the files there are the reference outputs of full runs. Run times in `list` are for a 16-core desktop.

`linear`, `boomerang` and `weighted` fill tables of minima round count by round count, and `all` runs them only with `--quick`. The tables are cached in `analysis/build` under a digest of the trail models (and, for `weighted`, of the weighted models and their weights), so a run resumes with the round counts still missing (`clean` deletes them). `--jobs N` searches up to N missing round counts at the same time, one solver each (default: the number of cores minus 2), and `--rounds R` caps the Areion-512 tables at R rounds; `--record` then notes the cap in the header. From 7 rounds of Areion-512 on, one round count takes hours to days or more, and more cores do not shorten it. `linear --rounds 7` (or `--rounds 8`) and `boomerang --rounds 7` compute the SAT tables of sections H and I and every product-rule estimate there, those marked `*` on window lower bounds; `results/linear.txt` (with `--rounds 8`) and `results/boomerang.txt` are such runs.

`--solver highs` fills the Areion-512 tables of `linear` and `weighted` with the MILP solver HiGHS (`py/milp.py`) instead, in tables of their own, and takes the round counts the SAT tables already hold from them; run `linear --rounds 7` first to have the SAT minima to 7 rounds (the seventh takes about 4 h; `--rounds 8` adds the eighth, about 18 h), or HiGHS computes those as well. `linear --rounds 10 --solver highs` adds the remaining Areion-512 minima to 10 rounds and prints the window bound over 15 rounds; `weighted --rounds 10 --linear-rounds 8 --solver highs` computes the weighted tables of sections H and I, the linear one to 8 rounds and the single-permutation one to 10 (the related-constant one by SAT to 14 rounds, each round count settled by its window bound) and prints the estimates; `results/linear_highs.txt` and `results/weighted_highs.txt` are such runs, and their output names the solver of every round count and the HiGHS version.

`--rc7p2` selects the `P2` form for the checks that run one table (default `shift`, the library's). `--rc7p1 pi` replaces word 7 of `P1` by the plain π word 7 (the published table applies a one-nibble shift) in every check except `ref`, and never in the comparisons with the library, for comparison.

`results/*_rc7p1-pi.txt` hold such runs of `oracle`, `related`, `refined`, `symmetry`, `bclr`, and `affine`. The refined Areion-256 bound becomes 153 for both `P2` forms; for the `P2` `pi` form the Areion-512 bound of section F becomes 237 and one coarse Areion-256 rotation bound becomes 45. None of those conclusions changes.

The Go program in `analysis/go` carries a copy of the library's purego rounds and constant tables, so that it can run reduced rounds and the `pi` table; its test pins that copy to the exported permutations.

| Directory | Contents |
|---|---|
| `go/` | reference rounds, oracle, feasibility tables, symmetry search, coset engine, chain weights, empirical checks |
| `py/` | byte-activity models (pysat, highspy) and the algebraic checks |
| `c/` | AES-NI program for integral sums of order 4 and 5 |
| `results/` | reference outputs |
