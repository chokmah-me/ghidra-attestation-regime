// AttestationRegime.java
// Three regimes of capability attestation for autonomous agents
// Operationalized for binary/firmware analysis per Bilar 2026 (#24)

package chokmah.plugin.attestation.model;

/**
 * Attestation regimes determine the ceiling on what any verification or
 * audit method can achieve for a function, before any analyst-hour is spent.
 *
 * Regime 1 (Deterministic, Bounded):
 *   Fully determined by inputs, bounded execution, no external data-dependent
 *   control flow. Formally verifiable at bounded cost.
 *   Binary signatures: no FP, no MMIO reads, all loops bounded, no indirect CF.
 *   Example: CRC, AES round, SHA-256 compression, fixed state machines.
 *
 * Regime 2 (Cooperative Stochastic, Fixed Configuration):
 *   Depends on stochastic external input assumed non-adversarial. Chernoff
 *   bounds apply: Theta((1/eps^2) log(1/delta)) observations suffice.
 *   Binary signatures: reads from sensor inputs, FP on external values,
 *   bounded branching on sensor readings.
 *   Example: sensor fusion, moving-average filters, PID controllers.
 *
 * Regime 3a (Adversarial Input Exposure):
 *   Processes data from untrusted source. Data-dependent control flow on
 *   adversarial input. Statistical testing insufficient regardless of sample.
 *   Binary signatures: reads from UART/Ethernet/network buffers, unannotated
 *   memory regions, downstream of unauthenticated protocol parsers.
 *   Example: Modbus TCP handlers, EtherNet/IP parsers, firmware updaters.
 *
 * Regime 3b (Provenance Check Flag -- NOT automated):
 *   Large unexplained constant tables (>= 256 entries) + data-dependent
 *   branching on table output. Requires human provenance verification.
 *   CRC tables and backdoor triggers look identical in binary.
 */
public enum AttestationRegime {

    REGIME_1("Regime 1", "Deterministic, Bounded", 0xFF4CAF50, "Formally verifiable"),
    REGIME_2("Regime 2", "Cooperative Stochastic", 0xFFFFEB3B, "Statistical testing applies"),
    REGIME_3A("Regime 3a", "Adversarial Input Exposure", 0xFFF44336, "White-box analysis required"),
    PROVENANCE_CHECK("Provenance Check", "Unexplained constant tables", 0xFFFF9800, "Human verification required"),
    UNCLASSIFIED("Unclassified", "Insufficient data", 0xFF9E9E9E, "Needs memory map annotation");

    private final String label;
    private final String description;
    private final int colorArgb;
    private final String verificationImplication;

    AttestationRegime(String label, String description, int colorArgb, String verificationImplication) {
        this.label = label;
        this.description = description;
        this.colorArgb = colorArgb;
        this.verificationImplication = verificationImplication;
    }

    public String getLabel() {
        return label;
    }

    public String getDescription() {
        return description;
    }

    /**
     * ARGB color for Ghidra Listing/Function Graph rendering.
     * Green = Regime 1, Yellow = Regime 2, Red = Regime 3a,
     * Orange = Provenance Check, Gray = Unclassified.
     */
    public int getColorArgb() {
        return colorArgb;
    }

    public String getVerificationImplication() {
        return verificationImplication;
    }

    /**
     * True for Regime 3 (adversarial stochastic). PRF-hardness wall:
     * no polynomial-query adaptive protocol succeeds when the agent class
     * can embed pseudorandom functions (#24).
     */
    public boolean isAdversarial() {
        return this == REGIME_3A || this == PROVENANCE_CHECK;
    }

    /**
     * Regime 3 dominates Regime 2. A function reading both sensor and
     * network input is Regime 3, not 2. Adversarial input dominates
     * cooperative stochastic (#24 decision tree priority).
     */
    public static AttestationRegime dominate(AttestationRegime a, AttestationRegime b) {
        if (a == null) return b;
        if (b == null) return a;
        int ra = rank(a);
        int rb = rank(b);
        return ra >= rb ? a : b;
    }

    private static int rank(AttestationRegime r) {
        return switch (r) {
            case UNCLASSIFIED -> 0;
            case REGIME_1 -> 1;
            case REGIME_2 -> 2;
            case PROVENANCE_CHECK -> 3;
            case REGIME_3A -> 4;
        };
    }

    @Override
    public String toString() {
        return label;
    }
}
