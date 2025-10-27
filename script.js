// script.js — Steganography / Hidden Payload Detector
// Works with index.html — shows suspiciousness percentage

const fileInput = document.getElementById("fileInput");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");

fileInput.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;

  reportEl.style.display = "none";
  statusEl.innerHTML = `<p>🔍 Analyzing <strong>${file.name}</strong> (${file.size} bytes)...</p>`;

  const ab = await readArrayBuffer(file);
  const result = await analyzeImage(ab, file);

  // Build the UI report
  let cssClass = result.level === "alert" ? "red" : result.level === "warn" ? "yellow" : "green";

  reportEl.innerHTML = `
    <div class="alert ${cssClass}">
      <strong>${result.message}</strong>
      <br><span class="small">Suspiciousness Score: ${result.score}%</span>
    </div>
    <table>
      <tr><th>File Name</th><td>${file.name}</td></tr>
      <tr><th>File Size</th><td>${file.size} bytes</td></tr>
      <tr><th>Tail Info</th><td>${result.tailSummary}</td></tr>
      <tr><th>LSB Info</th><td>${result.lsbSummary}</td></tr>
    </table>
  `;
  reportEl.style.display = "block";
  statusEl.innerHTML = "";
});


// ---------- Analyzer Logic ----------
async function analyzeImage(arrayBuffer, file) {
  const view = new Uint8Array(arrayBuffer);

  const isPNG = view[0] === 0x89 && view[1] === 0x50 && view[2] === 0x4E && view[3] === 0x47;
  const isJPG = view[0] === 0xFF && view[1] === 0xD8 && view[2] === 0xFF;
  let eofIndex = -1;

  // Find EOF markers
  if (isJPG) {
    for (let i = view.length - 2; i >= 0; i--) {
      if (view[i] === 0xFF && view[i + 1] === 0xD9) { eofIndex = i + 2; break; }
    }
  } else if (isPNG) {
    for (let i = view.length - 12; i >= 0; i--) {
      if (view[i + 4] === 0x49 && view[i + 5] === 0x45 && view[i + 6] === 0x4E && view[i + 7] === 0x44) {
        eofIndex = i + 12;
        break;
      }
    }
  }

  // Analyze tail (extra bytes after end-of-image)
  let tail = new Uint8Array(0);
  if (eofIndex > 0 && eofIndex < view.length) {
    tail = view.slice(eofIndex);
  }
  const tailInfo = analyzeTail(tail);

  // Analyze LSB (pixel noise pattern)
  const dataUrl = await readDataURL(file);
  const img = await loadImage(dataUrl);
  const imageData = getImageData(img);
  const lsbInfo = analyzeLSB(imageData);

  // Combine into one suspiciousness score (0–100)
  const score = Math.min(100, Math.round(tailInfo.score * 0.6 + lsbInfo.score * 0.4));

  let message = "✅ Image appears safe.";
  let level = "safe";
  if (score >= 60) {
    message = "🚨 ALERT: Suspicious hidden data likely present!";
    level = "alert";
  } else if (score >= 30) {
    message = "⚠️ Warning: Possible hidden content detected.";
    level = "warn";
  }

  return {
    level,
    score,
    message,
    tailSummary: tailInfo.summary,
    lsbSummary: lsbInfo.summary,
  };
}


// ---------- Utility Functions ----------
function analyzeTail(tail) {
  if (tail.length === 0) return { score: 0, summary: "No extra data found after image end." };

  const printable = printableFraction(tail);
  const entropy = shannonEntropy(tail);
  const sig = findSignature(tail);

  let score = 0;
  if (tail.length > 100) score += 25;
  if (printable > 0.3) score += 25;
  if (entropy > 6.5) score += 25;
  if (sig) score += 30;

  const summary = `Tail length: ${tail.length} bytes, printable ${(printable * 100).toFixed(1)}%, entropy ${entropy.toFixed(2)}, ${sig ? "found signature " + sig : "no known signature"}.`;
  return { score: Math.min(100, score), summary };
}

function analyzeLSB(imageData) {
  const data = imageData.data;
  let lsb0 = 0, lsb1 = 0;
  for (let i = 0; i < data.length; i += 4) {
    for (let j = 0; j < 3; j++) {
      (data[i + j] & 1) ? lsb1++ : lsb0++;
    }
  }
  const total = lsb0 + lsb1;
  const balance = Math.abs(lsb0 - lsb1) / total;
  const score = Math.min(100, Math.round((1 - balance) * 100)); // more even = more suspicious
  const summary = `LSB balance: ${(1 - balance).toFixed(2)}, 0s=${lsb0}, 1s=${lsb1}.`;
  return { score, summary };
}

function getImageData(img) {
  const maxPixels = 1_000_000;
  let scale = 1;
  if (img.width * img.height > maxPixels)
    scale = Math.sqrt(maxPixels / (img.width * img.height));
  const canvas = document.createElement("canvas");
  canvas.width = img.width * scale;
  canvas.height = img.height * scale;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  return ctx.getImageData(0, 0, canvas.width, canvas.height);
}

function findSignature(data) {
  const sigs = [
    { name: "ZIP", bytes: [0x50, 0x4B, 0x03, 0x04] },
    { name: "APK", bytes: [0x50, 0x4B, 0x03, 0x04] },
    { name: "PDF", bytes: [0x25, 0x50, 0x44, 0x46] },
    { name: "RAR", bytes: [0x52, 0x61, 0x72, 0x21] },
    { name: "EXE", bytes: [0x4D, 0x5A] },
  ];
  for (let i = 0; i < data.length - 8; i++) {
    for (let sig of sigs) {
      let match = true;
      for (let j = 0; j < sig.bytes.length; j++) {
        if (data[i + j] !== sig.bytes[j]) { match = false; break; }
      }
      if (match) return sig.name;
    }
  }
  return null;
}

function printableFraction(data) {
  let count = 0;
  for (let b of data) if (b >= 32 && b <= 126) count++;
  return data.length ? count / data.length : 0;
}

function shannonEntropy(bytes) {
  const freq = new Array(256).fill(0);
  for (let b of bytes) freq[b]++;
  let H = 0, n = bytes.length || 1;
  for (let c of freq) if (c) {
    const p = c / n;
    H -= p * Math.log2(p);
  }
  return H;
}

function readArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

function readDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function loadImage(dataUrl) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = dataUrl;
  });
}
