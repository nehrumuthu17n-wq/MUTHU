const API_BASE = ""; // same-origin

// ---------------------------------------------------------------
// Mode switching
// ---------------------------------------------------------------
const modeButtons = document.querySelectorAll(".mode-btn");
const forms = document.querySelectorAll(".analyze-form");

modeButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    modeButtons.forEach((b) => { b.classList.remove("active"); b.setAttribute("aria-selected", "false"); });
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");

    const mode = btn.dataset.mode;
    forms.forEach((f) => f.classList.toggle("active", f.id === `form-${mode}`));
  });
});

// ---------------------------------------------------------------
// Dropzone helpers (QR + Image forms)
// ---------------------------------------------------------------
function wireDropzone(dropzoneId, inputId, previewId) {
  const zone = document.getElementById(dropzoneId);
  const input = document.getElementById(inputId);
  const preview = document.getElementById(previewId);
  const hint = zone.querySelector(".dropzone-hint");

  zone.setAttribute("tabindex", "0");
  zone.setAttribute("role", "button");

  const showPreview = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      preview.src = e.target.result;
      preview.hidden = false;
      hint.style.display = "none";
    };
    reader.readAsDataURL(file);
  };

  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", () => showPreview(input.files[0]));

  ["dragenter", "dragover"].forEach((evt) =>
    zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.add("dragover"); })
  );
  ["dragleave", "drop"].forEach((evt) =>
    zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.remove("dragover"); })
  );
  zone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) {
      input.files = e.dataTransfer.files;
      showPreview(file);
    }
  });
}
wireDropzone("qr-dropzone", "qr-input", "qr-preview");
wireDropzone("image-dropzone", "image-input", "image-preview");

// ---------------------------------------------------------------
// Result panel elements
// ---------------------------------------------------------------
const resultEmpty = document.getElementById("result-empty");
const resultBody = document.getElementById("result-body");
const resultError = document.getElementById("result-error");
const resultLoading = document.getElementById("result-loading");

const gaugeFill = document.getElementById("gauge-fill");
const scoreNumber = document.getElementById("score-number");
const riskPill = document.getElementById("risk-pill");
const explicitPill = document.getElementById("explicit-pill");
const contentTypeTag = document.getElementById("content-type-tag");
const qrPayloadLine = document.getElementById("qr-payload-line");
const imageVerdictLine = document.getElementById("image-verdict-line");
const findingsList = document.getElementById("findings-list");
const recoList = document.getElementById("reco-list");
const linksSection = document.getElementById("links-section");
const linksList = document.getElementById("links-list");

const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 60; // r=60

function setPanelState(state) {
  resultEmpty.hidden = state !== "empty";
  resultBody.hidden = state !== "result";
  resultError.hidden = state !== "error";
  resultLoading.hidden = state !== "loading";
}

function riskColor(label) {
  const map = {
    "Trusted": "#45DD8F",
    "Low Risk": "#7CB518",
    "Moderate Risk": "#F5A83C",
    "High Risk": "#FF8A3D",
    "Critical Risk": "#FF6161",
  };
  return map[label] || "#35D8C8";
}

function renderResult(data) {
  setPanelState("result");

  const score = data.trust_score;
  const color = data.risk_color || riskColor(data.risk_level);

  scoreNumber.textContent = Math.round(score);
  scoreNumber.style.color = color;

  const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  gaugeFill.style.stroke = color;
  // reset then animate
  gaugeFill.style.transition = "none";
  gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  requestAnimationFrame(() => {
    gaugeFill.style.transition = "stroke-dashoffset 0.8s cubic-bezier(0.22,1,0.36,1), stroke 0.4s ease";
    gaugeFill.style.strokeDashoffset = offset;
  });

  riskPill.textContent = data.risk_level;
  riskPill.style.background = color + "26";
  riskPill.style.color = color;
  riskPill.style.border = `1px solid ${color}55`;

  const explicitFlag = data.details && data.details.safety && data.details.safety.explicit_content;
  if (explicitFlag) {
    explicitPill.hidden = false;
    explicitPill.style.display = "inline-flex";
    explicitPill.style.background = "rgba(255, 129, 82, 0.18)";
    explicitPill.style.color = "#ff9e6b";
    explicitPill.style.border = "1px solid rgba(255, 158, 107, 0.55)";
  } else {
    explicitPill.hidden = true;
    explicitPill.style.display = "none";
  }

  contentTypeTag.textContent = `Content type: ${data.content_type.toUpperCase()}`;

  if (data.content_type === "qr" && data.details && data.details.payload) {
    qrPayloadLine.hidden = false;
    qrPayloadLine.textContent = `Decoded: ${data.details.payload}`;
  } else {
    qrPayloadLine.hidden = true;
  }

  if (data.content_type === "image" && data.details && data.details.verdict) {
    imageVerdictLine.hidden = false;
    imageVerdictLine.textContent = `Authenticity: ${data.details.verdict}`;
    imageVerdictLine.style.color = data.details.verdict === "Likely original" ? "#45DD8F" : color;
  } else {
    imageVerdictLine.hidden = true;
  }

  findingsList.innerHTML = "";
  (data.reasons || []).forEach((f) => {
    const li = document.createElement("li");
    const tag = document.createElement("span");
    tag.className = `severity-tag sev-${f.severity}`;
    tag.textContent = f.severity;
    const msg = document.createElement("span");
    msg.textContent = f.message;
    li.appendChild(tag);
    li.appendChild(msg);
    findingsList.appendChild(li);
  });

  recoList.innerHTML = "";
  (data.recommendations || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    recoList.appendChild(li);
  });

  if (data.link_analysis && data.link_analysis.length) {
    linksSection.hidden = false;
    linksList.innerHTML = "";
    data.link_analysis.forEach((link) => {
      const li = document.createElement("li");
      const urlSpan = document.createElement("span");
      urlSpan.textContent = link.url;
      const scoreSpan = document.createElement("span");
      scoreSpan.className = "link-score";
      scoreSpan.textContent = `${Math.round(link.score)}/100`;
      scoreSpan.style.color = riskColor(
        link.score >= 80 ? "Trusted" : link.score >= 60 ? "Low Risk" : link.score >= 40 ? "Moderate Risk" : link.score >= 20 ? "High Risk" : "Critical Risk"
      );
      li.appendChild(urlSpan);
      li.appendChild(scoreSpan);
      linksList.appendChild(li);
    });
  } else {
    linksSection.hidden = true;
  }
}

function renderError(message) {
  setPanelState("error");
  resultError.textContent = message;
}

// ---------------------------------------------------------------
// Form submission handling
// ---------------------------------------------------------------
async function handleSubmit(form) {
  const endpoint = form.dataset.endpoint;
  const fileField = form.dataset.filefield;
  setPanelState("loading");

  try {
    let response;
    if (fileField) {
      const input = form.querySelector(`input[name="${fileField}"]`);
      if (!input.files || !input.files[0]) {
        renderError("Please choose an image file first.");
        return;
      }
      const fd = new FormData();
      fd.append(fileField, input.files[0]);
      response = await fetch(API_BASE + endpoint, { method: "POST", body: fd });
    } else {
      const formData = new FormData(form);
      const payload = Object.fromEntries(formData.entries());
      response = await fetch(API_BASE + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    }

    const data = await response.json();
    if (!response.ok) {
      renderError(data.error || "Something went wrong while analyzing this content.");
      return;
    }
    renderResult(data);
  } catch (err) {
    renderError(
      "Could not reach the Digital Trust Score server. Make sure the backend is running (see README) and try again."
    );
  }
}

forms.forEach((form) => {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    handleSubmit(form);
  });
});
