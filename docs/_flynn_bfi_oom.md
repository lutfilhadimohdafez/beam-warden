# flynn task: fix live-BFI OOM in stream_features (rotate/truncate)

## File
`tools/bfi_features.py` — function `stream_features` only (plus its live helpers if needed). Do NOT touch offline `extract_features`, decode/angle math, or the CLI contract.

## Bug (root cause)
Live BFI capture writes ALL packets to ONE temp pcap via `tshark -w tmp_path` with no rotation. Every 0.5s poll then re-parses the ENTIRE growing file: `_meta_rows` (`tshark -r`) and `_all_frame_bytes` (`tshark -x`, decodes every cat-30 frame in the whole file into a dict). Disk + memory climb without bound until OOM on long live runs.

Second bug fixed by the same change: `_all_frame_bytes` positionally `zip`s ALL cat-30 blocks in the file against only the NEW frame numbers passed in, so from the 2nd poll onward new frame numbers get paired with the OLDEST frames' bytes → wrong features.

## Required fix: bounded-burst capture (rotate the file)
Replace the "one long tshark + poll a growing file" model with a loop of SHORT bounded captures into a FRESH temp file each cycle:

Loop until stop_event set / overall deadline reached:
1. Capture one burst into a fresh empty temp pcap: `tshark -i iface -w tmp -a duration:BURST`. Use `BURST = 3` seconds. If `duration > 0`, clamp the burst so total capture time never exceeds `duration` (track an overall deadline).
2. Honor `stop_event`: if it is set, terminate the tshark subprocess promptly and break. Also break if the burst tshark exits with an error (collect stderr like the current code does).
3. After the burst finishes, decode the WHOLE (small) fresh pcap: get all cat-30 rows via `_meta_rows`, load bytes via `_all_frame_bytes` over the SAME file, then for each row call `_mimo_and_report` + `frame_to_features` and `yield` non-None feats. Because you process the full fresh file, `frame_numbers == all rows` so the positional zip stays aligned.
4. `os.unlink` the temp pcap (best-effort) before the next burst, so nothing accumulates on disk.

Persist `window_state` ACROSS bursts (create it once before the loop) so temporal-variance continuity is preserved. `local_counter` (frame_id) must also keep incrementing across bursts. `seen_frames` is no longer needed — each burst is a fresh file processed once.

Keep the existing final `finally` cleanup (terminate tshark, unlink last temp). Keep the function signature, docstring intent, and the `main()`/CLI usage unchanged.

## ponytail
- Update the docstring's latency note: latency ceiling is now ~BURST seconds (batchy), not 0.5s. Add a `# ponytail:` line naming that ceiling and that BURST is the tuning knob.
- No new deps. stdlib + subprocess + existing helpers only. Do not add threads if a straight blocking `subprocess.run(..., timeout=BURST+5)` per burst is enough — simpler is better. Only keep a background capture thread if you actually need one for stop_event responsiveness; a `subprocess.Popen` + poll-for-stop loop is fine.

## Test (leave one runnable check)
Add ONE `assert`-based test to `tools/test_bfi_features.py` that does NOT require tshark/root: monkeypatch/stub the burst-capture + decode helpers so `stream_features` runs against a fabricated fixed set of frames across TWO simulated bursts, and assert (a) it yields the expected number of feats and (b) `window_state` continuity holds (frame_id keeps climbing across the burst boundary). Keep it minimal — no frameworks, no fixtures beyond a stub.

Run the file's tests after: `.venv/bin/python -m pytest tools/test_bfi_features.py -q` (or `python tools/test_bfi_features.py` if it's a `__main__` self-check). Report pass/fail honestly.

## Storage safety (why this matters)
The OLD code left a gigabyte-sized temp pcap on disk whenever the run was OOM-killed (SIGKILL skips the `finally`). The burst design must keep each temp file SMALL (only BURST seconds of capture) and unlink it every cycle, so even a hard-killed run leaves at most a few MB, never gigabytes. This is a hard requirement, not a nicety.
