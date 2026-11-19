// In-browser engine for the live console (live/ on GitHub Pages, where there is no server).
// Replays CIC-IDS2017 test flows and scores each half-second batch with the detector's ONNX models in
// onnxruntime-web, then applies the same decision bands as app/detector.py. app/export_web.py checked
// that the ONNX models reach the Python detector's decision on every replay flow.
window.BrowserEngine = (() => {
  const TICK_MS = 500;
  let card, feats, X, view = [], scen = {}, sup, iso, ctl, onFlows, onStatus, pos = 0, ok = false, busy = false, loading;

  // Same transform as signed_log in src/cicids2017.py: NaN/inf -> 0, then sign(x) * log(1 + |x|)
  const signedLog = v => Number.isFinite(v) ? Math.sign(v) * Math.log1p(Math.abs(v)) : 0;

  async function load() {
    ort.env.wasm.wasmPaths = window.ORT_WASM;
    ort.env.wasm.numThreads = 1;  // GitHub Pages is not cross-origin isolated, so no wasm threads
    card = await fetch("model/card.json").then(r => r.json());
    feats = card.features_order;
    sup = await ort.InferenceSession.create("model/supervised.onnx");
    iso = await ort.InferenceSession.create("model/anomaly.onnx");

    const buf = new Uint8Array(await (await fetch("replay.csv.gz")).arrayBuffer());
    const gz = buf[0] === 0x1f && buf[1] === 0x8b;  // some hosts already decompress it
    const text = gz ? await new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream("gzip"))).text()
                    : new TextDecoder().decode(buf);
    const lines = text.split(/\r?\n/).filter(Boolean);
    const head = lines.shift().split(",");
    const col = Object.fromEntries(head.map((h, i) => [h, i]));
    const fi = feats.map(f => col[f]);
    if (fi.some(i => i === undefined)) throw new Error("replay file lacks model features");
    const rows = lines.map(l => l.split(",")).filter(r => r.length === head.length);  // no field contains a comma
    X = new Float32Array(rows.length * feats.length);
    rows.forEach((r, i) => {
      fi.forEach((c, j) => { X[i * feats.length + j] = signedLog(parseFloat(r[c])); });
      view.push({ ts: r[col.Timestamp], src: r[col["Src IP"]], sport: +r[col["Src Port"]], dst: r[col["Dst IP"]],
                  dport: +r[col["Dst Port"]], proto: +r[col.Protocol], label: r[col.Label], technique: r[col.technique],
                  scenario: r[col.scenario] });
    });
    view.forEach((v, i) => (scen[v.scenario] ??= []).push(i));
    scen.mixed = view.map((_, i) => i).sort((a, b) => view[a].ts < view[b].ts ? -1 : view[a].ts > view[b].ts ? 1 : a - b);
  }

  const loaded = () => loading ??= load();

  function decide(p, anomaly) {
    return p >= card.thresholds.alert ? "ALERT" : (p >= card.thresholds.review || anomaly) ? "REVIEW" : "ALLOW";
  }

  async function tick() {
    if (!ok || ctl.paused || busy) return;
    busy = true;
    try {
      const order = scen[ctl.scenario] || scen.mixed, n = Math.max(1, Math.round(ctl.speed * TICK_MS / 1000)), F = feats.length;
      const idx = Array.from({ length: n }, (_, k) => order[(pos + k) % order.length]);
      pos = (pos + n) % order.length;
      const x = new Float32Array(n * F);
      idx.forEach((r, k) => x.set(X.subarray(r * F, (r + 1) * F), k * F));
      const t0 = performance.now();
      const input = { x: new ort.Tensor("float32", x, [n, F]) };
      const proba = (await sup.run(input)).probabilities.data;
      const scores = (await iso.run(input)).scores.data;
      const latency = performance.now() - t0;
      const flows = idx.map((r, k) => {
        const p = proba[2 * k + 1], anomaly = scores[k] < card.anomaly_threshold;
        return { ...view[r], supervised: p, anomaly_score: scores[k], anomaly, decision: decide(p, anomaly) };
      });
      onFlows({ type: "flows", scenario: ctl.scenario, latency_ms: latency, flows });
    } catch (e) {
      onStatus("Scoring failed: " + e.message);
    } finally {
      busy = false;
    }
  }

  return {
    where: "in your browser",
    live: "Scoring in your browser",
    note: "Scores are computed live in your browser: the detector runs as ONNX models in onnxruntime-web, with no server.",
    start(c, f, s) {
      ctl = c; onFlows = f; onStatus = s;
      s("Loading the model…");
      loaded().then(() => { ok = true; s(); setInterval(tick, TICK_MS); })
              .catch(e => s("Could not load the model: " + e.message));
    },
    send(patch) { if ("scenario" in patch) pos = 0; },
    ready: () => ok,
    model: () => loaded().then(() => card),
  };
})();
