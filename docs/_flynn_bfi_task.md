# TASK: BFI → CSI-variance feature bridge (`tools/bfi_features.py`)

You are Flynn (implementer). Build ONE new file: `tools/bfi_features.py`.
It decodes captured HE Compressed Beamforming Reports (BFI) into steering-angle
matrices and emits per-frame CSI-style features (phase/amplitude geometry,
multipath spread, CSI-matrix variance) as a CSV the anomaly detector can consume.

Ponytail: minimal, stdlib + numpy only. NO scapy, NO new deps. tshark is already
required by `tools/bfi_capture.py`. Do NOT reconstruct the full V matrix — the
angles ARE a sufficient CSI proxy for variance features.
`# ponytail: angles-only; add reconstruct_V() only if V-condition features are needed later`

## Input (verified on data/bfi_he_capture.pcap: 171 HE frames, Nr=2 Nc=2 SU cb0)

Report bytes are NOT a named tshark field in Wireshark 4.7.3. Extract them from the
raw frame. USE THIS VERIFIED EXTRACTION (already tested — do not redesign it):

```python
import subprocess, re
import numpy as np

def _meta_rows(pcap):
    """Return list of (frame_number, mimo_ctrl_uint40_hex, report_len) for HE BFI frames."""
    out = subprocess.run(
        ["tshark","-r",pcap,"-Y","wlan.fixed.category_code==30","-T","fields",
         "-e","frame.number","-e","wlan.he.action.he_mimo_control",
         "-e","wlan.he.action.he_mimo_control.report_len"],
        capture_output=True, text=True).stdout.splitlines()
    rows=[]
    for line in out:
        parts=line.split("\t")
        if len(parts)>=3 and parts[1]:
            rows.append((parts[0], parts[1], int(parts[2]) if parts[2] else 0))
    return rows

def _frame_bytes(pcap, fn):
    raw = subprocess.run(["tshark","-r",pcap,"-Y",f"frame.number=={fn}","-x"],
                         capture_output=True, text=True).stdout
    out=bytearray()
    for line in raw.splitlines():
        m=re.match(r'^([0-9a-fA-F]{4,})\s+((?:[0-9a-fA-F]{2} ?){1,16})', line)
        if m:
            for tok in m.group(2).split():
                out.append(int(tok,16))
    return bytes(out)

def _mimo_and_report(pcap, fn, mc_hex, report_len):
    val = int(mc_hex,16)
    mc_bytes = bytes((val>>(8*i))&0xff for i in range(5))       # uint40 LE -> 5 bytes
    nc = (val & 0x7)+1
    nr = ((val>>3)&0x7)+1
    codebook = (val>>9)&0x1
    feedback_type = (val>>10)&0x3
    fb = _frame_bytes(pcap, fn)
    idx = fb.find(mc_bytes)
    # report follows the 5-byte MIMO control; drop trailing 4-byte FCS if present
    report = fb[idx+5:] if idx>=0 else b""
    if len(report) > 4:
        report = report[:-4]   # strip FCS; # ponytail: FCS drop, exact if radiotap has_fcs varies
    return dict(nr=nr, nc=nc, codebook=codebook, feedback_type=feedback_type, report=report)
```
Notes: mimo-control low bytes are constant across the capture (Nr/Nc/cb/fb fixed);
only SCIDX varies. report slice ≈ 190 bytes (report_len field reads 197 but includes
trailing fields not fully present — decode from the sliced bytes, derive Nst from
available bits).

## Decode math — PORT THIS C++ EXACTLY (from BeamCraft main_su.cpp, validated)

```cpp
int compute_NANG(int Nr, int Nc){int nang=0,p=std::min(Nc,Nr-1);
  for(int i=1;i<=p;i++) nang+=2*(Nr-i); return nang;}

void get_bitwidths(int feedback_type,int codebook,int&b_phi,int&b_psi){
  if(feedback_type==0){ if(codebook==0){b_phi=4;b_psi=2;} else {b_phi=6;b_psi=4;} }     // SU
  else if(feedback_type==1){ if(codebook==0){b_phi=7;b_psi=5;} else {b_phi=9;b_psi=7;} } // MU
  else { b_phi=4; b_psi=2; } }

// decode_report_angles: CRITICAL bit order
double pow_phi=pow(2,b_phi), pow_psi=pow(2,b_psi+2);   // NOTE: psi uses b_psi+2
// build bitstring: for each byte, take bitset<8> (MSB-first) then REVERSE it (-> LSB-first), concat
// then per subcarrier kk in 0..Nst-1:
//   angcnt=0
//   for ii = Nr-1 down to max(Nr-Nc,1):
//     for jj in 0..ii-1:  read b_phi bits, REVERSE the slice, val; angles[angcnt,kk]=(2*val+1)/pow_phi; angcnt++
//     for jj in 0..ii-1:  read b_psi bits, REVERSE the slice, val; angles[angcnt,kk]=(2*val+1)/pow_psi; angcnt++
```
Porting rules (do NOT deviate):
- Per byte: `f"{byte:08b}"[::-1]` (MSB-first then reversed = LSB-first). Concatenate all bytes into one bit string.
- Read each angle: take the next `b_phi`/`b_psi` chars, REVERSE that slice, `int(slice,2)`.
- phi value = `(2*raw+1)/2**b_phi`; psi value = `(2*raw+1)/2**(b_psi+2)`.
- All angle values must land in (0,1).
- Derive `Nst`: bits_per_sc = (NANG//2)*(b_phi+b_psi); Nst = total_bits // bits_per_sc.
  (NANG is even; per subcarrier #phi==#psi==NANG//2.)
- Build a boolean list `is_phi[angcnt]` in the SAME loop order so features can split phi vs psi generically (works for any Nr,Nc, not just 2x2).

Return `angles` as np.ndarray shape (NANG, Nst), plus is_phi mask.

## Features — one row per BFI frame
Columns (all floats unless noted):
- `frame` (int), `nr` (int), `nc` (int), `nst` (int), `nang` (int)
- `bfi_phi_mean`  = mean of all phi-angle entries
- `bfi_psi_mean`  = mean of all psi-angle entries
- `bfi_angle_var` = variance over the whole angles matrix   # CSI-matrix variance proxy
- `bfi_subcarrier_var` = mean over rows of var-across-subcarriers(axis=1)  # multipath / freq-selectivity
- `bfi_phi_temporal_var`, `bfi_psi_temporal_var` = rolling variance of this frame's phi_mean/psi_mean
  over the trailing window of W=10 frames (0.0 until the window fills)

## CLI
`python tools/bfi_features.py --pcap data/bfi_he_capture.pcap --out data/bfi_features.csv [--window 10]`
Print a one-line summary: N frames decoded, Nr/Nc/Nst, feature column means.

## Self-check (ponytail: exactly ONE runnable check, assert-based)
Add `if __name__ == "__main__"` OR a `test_bfi_features.py` with a `demo()`:
Run on `data/bfi_he_capture.pcap` and assert:
- decodes > 100 HE frames
- every angle value is in the open interval (0, 1)
- angles.shape == (NANG, Nst) with Nst > 0 and NANG == compute_NANG(Nr,Nc)
- output CSV has one row per decoded frame + all feature columns present
Keep it dependency-free (numpy ok). No pytest fixtures.

## Constraints
- One file (+ optional one small test). Reuse nothing from main_su.cpp at runtime (it's C++, gitignored).
- Match existing repo style (see tools/bfi_capture.py, tools/train_detector.py).
- Do not modify other files.
