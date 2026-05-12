// RegimeAssigner.java
// Step 4: Regime Assignment (Decision Tree)
//
// IF all inputs constant/internal
//    AND all loops bounded
//    AND no indirect CF:
//     -> Regime 1
//
// ELIF any input is Regime 3a source (network/comms/unclassified):
//     -> Regime 3a
//
// ELIF complexity exceeds provenance-check threshold:
//     -> Flag for provenance check (possible 3b)
//
// ELIF any input is Regime 2 source (sensor/ADC):
//     -> Regime 2
//
// ELSE:
//     -> Regime 1
//
// KEY: Regime 3 checks come BEFORE Regime 2.
// A function reading both sensors and network input is Regime 3, not 2.
// Adversarial input dominates.

package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;

import java.util.List;

/**
 * Decision tree for assigning attestation regime based on prior analysis
 * steps. Implements the priority rule: adversarial input dominates all.
 */
public class RegimeAssigner {

    private final boolean strictMode;

    /**
     * @param strictMode if true, defaults unclassified to Regime 3a
     *                   (conservative). If false, unclassified stays
     *                   unclassified for analyst review.
     */
    public RegimeAssigner(boolean strictMode) {
        this.strictMode = strictMode;
    }

    /**
     * Step 4: Assign regime using the priority decision tree.
     *
     * @param sources    tagged input sources from Step 1
     * @param cfProps    control flow properties from Step 2
     * @param complexity complexity metrics from Step 3
     * @return assigned regime with rationale string
     */
    public RegimeAssignment assignRegime(
            List<InputSource> sources,
            ControlFlowProperties cfProps,
            ComplexityMetrics complexity) {

        StringBuilder rationale = new StringBuilder();

        // Check 1: Any Regime 3a input source?
        // Priority: adversarial input dominates everything
        boolean hasRegime3Input = sources.stream()
                .anyMatch(s -> {
                    InputSource.SourceType t = s.getSourceType();
                    if (t == InputSource.SourceType.NETWORK_COMMS ||
                            t == InputSource.SourceType.UNCLASSIFIED_EXT ||
                            t == InputSource.SourceType.MMIO_UNKNOWN) {
                        return true;
                    }
                    if (t == InputSource.SourceType.INTERNAL_STATE) {
                        return s.getInheritedRegime() == AttestationRegime.REGIME_3A;
                    }
                    return false;
                });

        if (hasRegime3Input) {
            InputSource trigger = sources.stream()
                    .filter(s -> {
                        InputSource.SourceType t = s.getSourceType();
                        return t == InputSource.SourceType.NETWORK_COMMS ||
                                t == InputSource.SourceType.UNCLASSIFIED_EXT ||
                                t == InputSource.SourceType.MMIO_UNKNOWN;
                    })
                    .findFirst().orElse(null);

            rationale.append("Regime 3a: function reads from adversarial/untrusted source. ");
            if (trigger != null) {
                rationale.append("Trigger: ").append(trigger.getDescription()).append(". ");
            }
            rationale.append("Adversarial input dominates per #24 decision tree.");

            return new RegimeAssignment(AttestationRegime.REGIME_3A,
                    Confidence.MEDIUM, rationale.toString());
        }

        // Check 2: Provenance check threshold?
        // Large unexplained tables with data-dependent branching
        if (complexity.isProvenanceCheckCandidate()) {
            rationale.append("Flagged for provenance check: large unexplained constant table(s) ");
            rationale.append("(").append(complexity.lookupTableEntries()).append(" entries) ");
            rationale.append("with data-dependent branching. ");
            rationale.append("Table contents must be verified against known standards ");
            rationale.append("(CRC polynomial, IEEE 754, published curves). ");
            rationale.append("If unexplained, this is a supply-chain flag. ");
            rationale.append("Human decision required.");

            Confidence conf = complexity.provenanceCheckScore() > 5.0 ?
                    Confidence.HIGH : Confidence.MEDIUM;

            return new RegimeAssignment(AttestationRegime.PROVENANCE_CHECK,
                    conf, rationale.toString());
        }

        // Check 3: Regime 1 determinism?
        // All inputs constant or internal with Regime 1 provenance, all loops bounded, no indirect CF
        boolean allInputsDeterministic = sources.stream()
                .allMatch(s -> {
                    InputSource.SourceType t = s.getSourceType();
                    if (t == InputSource.SourceType.CONSTANT) {
                        return true;
                    }
                    if (t == InputSource.SourceType.INTERNAL_STATE) {
                        // Only deterministic if inherited regime is REGIME_1
                        return s.getInheritedRegime() == AttestationRegime.REGIME_1;
                    }
                    return false;
                });

        boolean isRegime1 = allInputsDeterministic
                && cfProps.allLoopsBounded()
                && !cfProps.hasIndirectControlFlow()
                && !cfProps.hasFloatingPoint();

        if (isRegime1) {
            rationale.append("Regime 1: all inputs are constant/internal with Regime 1 provenance. ");
            rationale.append("All loops bounded (").append(cfProps.loopCount()).append("). ");
            rationale.append("No indirect control flow. ");
            rationale.append("Formally verifiable at bounded cost.");

            // Lower confidence if we inferred this from absence of data (empty sources)
            Confidence conf = sources.isEmpty() ? Confidence.MEDIUM : Confidence.HIGH;
            return new RegimeAssignment(AttestationRegime.REGIME_1,
                    conf, rationale.toString());
        }

        // Check 4: Regime 2 stochastic input?
        // Sensor/ADC reads present, or INTERNAL_STATE with Regime 2 inherited, no adversarial input (already checked)
        boolean hasRegime2Input = sources.stream()
                .anyMatch(s -> {
                    InputSource.SourceType t = s.getSourceType();
                    if (t == InputSource.SourceType.SENSOR_ADC) {
                        return true;
                    }
                    if (t == InputSource.SourceType.INTERNAL_STATE) {
                        return s.getInheritedRegime() == AttestationRegime.REGIME_2;
                    }
                    return false;
                });

        if (hasRegime2Input) {
            rationale.append("Regime 2: function reads from sensor/ADC inputs. ");
            rationale.append("Chernoff bounds apply: Theta((1/eps^2) log(1/delta)) ");
            rationale.append("observations suffice. No adversarial input detected.");

            return new RegimeAssignment(AttestationRegime.REGIME_2,
                    Confidence.MEDIUM, rationale.toString());
        }

        // Fallback: No external inputs detected at all -> Regime 1 (pure computation)
        if (sources.isEmpty()) {
            if (!cfProps.hasIndirectControlFlow() && cfProps.allLoopsBounded()) {
                rationale.append("Regime 1: no external memory reads detected. ");
                rationale.append("Pure computation with bounded loops.");
                return new RegimeAssignment(AttestationRegime.REGIME_1,
                        Confidence.MEDIUM, rationale.toString());
            } else {
                rationale.append("Regime 1: no external inputs. Unbounded loops or ");
                rationale.append("indirect CF present but without external data dependency.");
                return new RegimeAssignment(AttestationRegime.REGIME_1,
                        Confidence.LOW, rationale.toString());
            }
        }

        // Unclassified: some inputs we couldn't categorize
        if (strictMode) {
            rationale.append("Regime 3a (strict mode): unclassified input sources. ");
            rationale.append("Conservative default to adversarial.");
            return new RegimeAssignment(AttestationRegime.REGIME_3A,
                    Confidence.LOW, rationale.toString());
        } else {
            rationale.append("Unclassified: unable to determine input regime. ");
            rationale.append("Requires memory map annotation (SVD or manual JSON).");
            return new RegimeAssignment(AttestationRegime.UNCLASSIFIED,
                    Confidence.LOW, rationale.toString());
        }
    }

    /**
     * Immutable result of regime assignment.
     */
    public record RegimeAssignment(
            AttestationRegime regime,
            Confidence confidence,
            String rationale
    ) {
    }
}
