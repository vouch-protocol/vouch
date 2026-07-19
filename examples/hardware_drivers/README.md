# Reference hardware drivers for the Vouch disconnected-edge seam

The Vouch disconnected-edge trust primitives (`vouch.robotics.presence`,
`localization`, `edge_trust`, `freshness`, …) are deterministic verifier
predicates over signed **measurements**. Where those measurements come from —
a ranging radio, a laser terminal's attitude, a navigation fix, a clock, a
radiation monitor, a relay's epoch counter — is platform-specific. That boundary
is `vouch.robotics.hardware`: a set of typed Protocols your drivers implement.

This directory is a **skeleton you copy and fill in**. The trust logic never
changes; you only supply device reads.

## What you implement

Each Protocol in `vouch.robotics.hardware` (mirrored as a stub in `drivers.py`):

| Protocol | Method(s) | Typical source |
| --- | --- | --- |
| `NavigationSource` | `position()`, `velocity()` | GNSS, INS, star tracker, odometry |
| `RangeSensor` | `measure_range_m(target)` | RF time-of-flight, UWB, laser ranging, acoustic |
| `DopplerSensor` | `measure_doppler_hz(target, carrier_hz)` | receiver frequency estimator |
| `PointingSource` | `pointing()`, `beamwidth_rad()` | gimbal / ADCS attitude |
| `ClockSource` | `time_quality()` | GNSS-disciplined clock, CSAC, oscillator model |
| `EpochSource` | `current_epoch()` | DTN control plane / relay beacon |
| `IntegrityMonitor` | `cumulative_risk()`, `metrics()` | dosimeter, ECC/SEU counters |

The Protocols are `runtime_checkable`, so you do **not** need to inherit anything —
matching the method signatures is enough. `isinstance(MyRadio(), RangeSensor)` is
`True` for any class with the right method.

## How to use it

1. Copy `drivers.py` into your platform and replace each `raise
   NotImplementedError` with a real device read.
2. Check your progress:

   ```bash
   python examples/hardware_drivers/drivers.py
   ```

   It prints a checklist of which drivers are implemented.

3. Hand your driver objects to the capture / verify-live adapters, exactly as the
   reference `Simulated*` classes are used in
   [`examples/hardware_seam_demo.py`](../hardware_seam_demo.py):

   ```python
   from vouch.robotics import capture_presence_attestation, verify_presence_live

   att = capture_presence_attestation(
       signer, peer_did=peer, nonce=nonce,
       claimed_position=peer_claimed_xyz,
       range_sensor=MyRangeSensor(),      # your driver
       tolerance_m=1.0,
   )
   ok, subject = verify_presence_live(att, peer_key, nav=MyNavigation())  # your driver
   ```

## What stays yours vs. ours

- **Yours:** the driver bodies (talking to real silicon), the frame convention
  (keep positions/velocities in one consistent metric frame), and how you derive
  clock uncertainty and integrity risk for your hardware.
- **Ours (unchanged):** the credential formats, the signatures, and every trust
  predicate (range consistency, triangulation threshold, kinematic reachability,
  staleness/epoch gates, quarantine/quorum logic).

See [`docs/robotics.md`](../../docs/robotics.md) for the full module map and the
PAD disclosures (PAD-106 to PAD-124) for the design rationale.
