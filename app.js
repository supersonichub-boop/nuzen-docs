(() => {
  "use strict";

  const KEY_STORE = "nuzen.key";
  const $ = (s, el = document) => el.querySelector(s);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const PDFJS = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/";

  let vault = null;
  let master = null;
  let manifest = null;
  const docsById = new Map();

  if (window.pdfjsLib) pdfjsLib.GlobalWorkerOptions.workerSrc = PDFJS + "pdf.worker.min.js";

  // ---------- key storage (may be unavailable in private mode) ----------
  const store = {
    get() { try { return localStorage.getItem(KEY_STORE) || sessionStorage.getItem(KEY_STORE); } catch { return null; } },
    set(v, remember) { try { (remember ? localStorage : sessionStorage).setItem(KEY_STORE, v); } catch { /* ignore */ } },
    clear() { try { localStorage.removeItem(KEY_STORE); sessionStorage.removeItem(KEY_STORE); } catch { /* ignore */ } },
  };

  // ---------- crypto ----------
  const unseal = (key, bytes) => crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));

  async function loadVault() {
    if (vault) return vault;
    const res = await fetch("vault.json", { cache: "no-cache" });
    if (!res.ok) throw new Error("vault");
    return (vault = await res.json());
  }

  async function keyFromPassword(pw) {
    const v = await loadVault();
    const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
    const kek = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: b64(v.salt), iterations: v.iter },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    return unseal(kek, b64(v.key));
  }

  async function useMaster(raw) {
    const v = await loadVault();
    master = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    manifest = JSON.parse(dec.decode(await unseal(master, b64(v.manifest))));
  }

  // ---------- lock ----------
  const lock = $("#lock");
  const app = $("#app");
  const msg = $("#lockMsg");

  async function boot() {
    if (!window.crypto || !crypto.subtle) return showLock("เบราว์เซอร์นี้เปิดแฟ้มไม่ได้ ลองเปิดด้วย Chrome หรือ Safari รุ่นใหม่");
    const saved = store.get();
    if (saved) {
      try { await useMaster(b64(saved)); return showApp(false); } catch { store.clear(); }
    }
    showLock();
  }

  function showLock(text = "") {
    app.hidden = true;
    lock.hidden = false;
    msg.textContent = text;
    msg.classList.remove("is-busy");
    setTimeout(() => $("#pw").focus(), 50);
  }

  $("#lockForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $("#pw").value.trim().toLowerCase();
    if (!pw) return;
    const btn = $("#unlockBtn");
    btn.disabled = true;
    msg.classList.add("is-busy");
    msg.textContent = "กำลังเปิดแฟ้ม…";
    try {
      const raw = await keyFromPassword(pw);
      await useMaster(raw);
      store.set(toB64(raw), $("#remember").checked);
      $("#pw").value = "";
      showApp(true);
    } catch (err) {
      msg.classList.remove("is-busy");
      msg.textContent = err && err.message === "vault"
        ? "โหลดแฟ้มไม่สำเร็จ ตรวจอินเทอร์เน็ตแล้วลองอีกครั้ง"
        : "รหัสผ่านไม่ถูกต้อง ตรวจตัวอักษรและขีดกลางอีกครั้ง";
    } finally {
      btn.disabled = false;
    }
  });

  $("#logout").addEventListener("click", () => {
    store.clear();
    master = null;
    manifest = null;
    $("#cases").innerHTML = "";
    showLock();
  });

  // ---------- helpers ----------
  const STATE = { ok: "มีครบแล้ว", partial: "มีบางส่วน", missing: "ยังขาด" };
  const ORDER = { ok: 0, partial: 1, missing: 2 };
  const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
  const typeOf = (m) => (m === "application/pdf" ? "PDF" : m === "image/png" ? "รูปภาพ PNG" : "รูปภาพ JPG");
  const extOf = (m) => (m === "application/pdf" ? ".pdf" : m === "image/png" ? ".png" : ".jpg");
  const metaOf = (d) => [typeOf(d.mime), d.mime === "application/pdf" && d.pages ? d.pages + " หน้า" : "", fmtSize(d.size)].filter(Boolean).join(", ");

  function splitName(name) {
    const m = name.match(/^(\d+\.\d+)\s+(.*)$/);
    return m ? { no: m[1], title: m[2] } : { no: "", title: name.replace(/_/g, " ") };
  }
  const refsFor = (c, ref) => c.docs.filter((d) => d.no === ref || d.group.startsWith(ref));

  // ---------- render ----------
  function showApp(animate) {
    lock.hidden = true;
    app.hidden = false;
    docsById.clear();
    manifest.cases.forEach((c) => c.docs.forEach((d) => {
      Object.assign(d, splitName(d.name));
      d.caseNo = c.folder;
      docsById.set(d.id, d);
    }));
    render();
    if (animate) {
      app.classList.add("is-building");
      setTimeout(() => app.classList.remove("is-building"), 2400);
    }
  }

  function render() {
    const cases = manifest.cases;
    const items = cases.flatMap((c) => c.checklist);
    const nDocs = cases.reduce((a, c) => a + c.docs.length, 0);
    const nPages = cases.reduce((a, c) => a + c.docs.reduce((x, d) => x + (d.pages || 0), 0), 0);
    const nMissing = items.filter((i) => i.status === "missing").length;
    const nPartial = items.filter((i) => i.status === "partial").length;

    $("#lead").innerHTML =
      `เอกสาร <b>${nDocs} ไฟล์</b> รวม ${nPages.toLocaleString("th-TH")} หน้า ใน ${cases.length} คดี ` +
      (nMissing || nPartial
        ? `ตอนนี้ยังขาดเอกสาร <b class="red">${nMissing} รายการ</b> และมีอีก ${nPartial} รายการที่ยังไม่ครบ`
        : "เอกสารครบทุกรายการแล้ว");
    $("#rev").textContent = "· ปรับปรุงล่าสุด " + manifest.generated;

    drawElevation(cases);

    $("#bays").innerHTML = cases.map((c) => {
      const open = c.checklist.filter((i) => i.status !== "ok").length;
      const done = c.checklist.length - open;
      return `<a class="bay" href="#case-${c.folder}">
          <div class="bay__no">คดีที่ ${esc(c.folder)}</div>
          <div class="bay__title">${esc(c.title)}</div>
          <div class="bay__state">ครบ ${done} จาก ${c.checklist.length}${open ? `, <span class="red">ต้องตามอีก ${open}</span>` : ""}</div>
        </a>`;
    }).join("");

    const pending = cases.flatMap((c) => c.checklist.filter((i) => i.status !== "ok").map((i) => ({ c, i })))
      .sort((a, b) => ORDER[b.i.status] - ORDER[a.i.status]);
    $("#todoList").innerHTML = pending.map(({ c, i }) => `
      <li>
        <i class="slab ${i.status}" title="${STATE[i.status]}"></i>
        <div>
          <div class="todo__item">${esc(i.item)}</div>
          <div class="todo__note">${STATE[i.status]}${i.note ? " — " + esc(i.note) : ""}</div>
        </div>
        <a class="todo__case" href="#case-${c.folder}">คดีที่ ${esc(c.folder)} ${esc(c.title)}</a>
      </li>`).join("");
    $("#todo").hidden = pending.length === 0;

    $("#cases").innerHTML = cases.map(renderCase).join("");
    filter("");
  }

  function drawElevation(cases) {
    const svg = $("#elev");
    const ground = 300, floorH = 42, x0 = 60, bayW = 280;
    const xs = cases.map((_, i) => x0 + i * bayW).concat(x0 + cases.length * bayW);
    const tops = cases.map((c) => ground - c.checklist.length * floorH);
    let out = `<title id="elevTitle">ความครบถ้วนของเอกสารแต่ละคดี</title>`;

    out += `<rect x="0" y="${ground}" width="960" height="92" fill="url(#earth)"/>`;
    xs.forEach((x, i) => {
      // piles under each column and mid-bay
      [x, i < cases.length ? x + bayW / 2 : null].forEach((px) => {
        if (px == null) return;
        out += `<line class="pile" x1="${px}" y1="${ground}" x2="${px}" y2="${ground + 72}"/>`;
        out += `<path class="pile-tip" d="M${px - 5} ${ground + 72}h10l-5 9z"/>`;
      });
    });
    out += `<line class="ground" x1="0" y1="${ground}" x2="960" y2="${ground}"/>`;
    out += `<text class="dim-text" x="4" y="${ground - 8}">±0.00</text>`;

    cases.forEach((c, b) => {
      const bx = xs[b];
      const slabs = [...c.checklist].sort((p, q) => ORDER[p.status] - ORDER[q.status]);
      let g = `<a href="#case-${c.folder}" aria-label="คดีที่ ${esc(c.folder)} ${esc(c.title)}">`;
      g += `<rect class="bay-hit" x="${bx + 2}" y="${tops[b] - 6}" width="${bayW - 4}" height="${ground - tops[b] + 6}" rx="4"/>`;
      slabs.forEach((it, k) => {
        const y = ground - (k + 1) * floorH;
        g += `<line class="beam" x1="${bx}" y1="${y}" x2="${bx + bayW}" y2="${y}"/>`;
        g += `<g class="slab-g" style="--d:${(0.15 + k * 0.12 + b * 0.06).toFixed(2)}s"><rect class="s-${it.status}" x="${bx + 14}" y="${y + 8}" width="${bayW - 28}" height="${floorH - 16}" rx="1.5"><title>${esc(it.item)} — ${STATE[it.status]}</title></rect></g>`;
      });
      g += `<line class="roof" x1="${bx - 8}" y1="${tops[b]}" x2="${bx + bayW + 8}" y2="${tops[b]}"/>`;
      g += `</a>`;
      out += g;
    });
    xs.forEach((x, i) => {
      const top = Math.min(tops[i - 1] ?? Infinity, tops[i] ?? Infinity);
      out += `<line class="col" x1="${x}" y1="${top}" x2="${x}" y2="${ground}"/>`;
    });
    svg.setAttributeNS(null, "viewBox", `0 0 960 ${ground + 92}`);
    svg.innerHTML = out;
  }

  function renderCase(c) {
    const okN = c.checklist.filter((i) => i.status === "ok").length;
    const checklist = c.checklist.map((i) => {
      const chips = i.refs.filter((r) => refsFor(c, r).length)
        .map((r) => `<button class="chip" type="button" data-ref="${esc(r)}" data-case="${esc(c.folder)}">${esc(r)}</button>`).join("");
      return `
        <li>
          <i class="slab ${i.status}" title="${STATE[i.status]}"></i>
          <div>
            <div class="check__item">${esc(i.item)}${i.status !== "ok" ? `<span class="check__state ${i.status}">${STATE[i.status]}</span>` : ""}</div>
            ${i.note ? `<div class="check__note">${esc(i.note)}</div>` : ""}
            ${chips ? `<div class="chips">${chips}</div>` : ""}
          </div>
        </li>`;
    }).join("");

    let lastGroup = "";
    const rows = c.docs.map((d) => {
      let head = "";
      if (d.group !== lastGroup) {
        lastGroup = d.group;
        if (d.group) head = `<div class="group" data-group="${esc(d.group)}">${esc(d.group)}</div>`;
      }
      return head + `
        <button class="row" type="button" data-id="${d.id}" data-group="${esc(d.group)}" data-q="${esc((d.no + " " + d.title + " " + d.group).toLowerCase())}">
          <span class="row__no">${esc(d.no)}</span>
          <span><span class="row__name">${esc(d.title)}</span><span class="row__meta">${metaOf(d)}</span></span>
          <span class="row__open">เปิดดู</span>
        </button>`;
    }).join("");

    return `
      <section class="case" id="case-${c.folder}">
        <div class="case__head">
          <div class="case__no" aria-hidden="true">${esc(c.folder)}</div>
          <div class="case__intro">
            <h2>${esc(c.title)}</h2>
            <div class="case__en">${esc(c.title_en)}</div>
            <p>${esc(c.summary)}</p>
          </div>
        </div>
        <div class="case__part">
          <h3 class="part-title">เอกสารที่คดีนี้ต้องใช้ <small>ครบ ${okN} จาก ${c.checklist.length}</small></h3>
          <ul class="checklist">${checklist}</ul>
        </div>
        <div class="case__part">
          <h3 class="part-title">ไฟล์ในแฟ้ม <small>${c.docs.length} ไฟล์</small></h3>
          <div class="register">${rows}<div class="empty" hidden>ไม่พบเอกสารที่ตรงกับคำค้นในคดีนี้</div></div>
        </div>
      </section>`;
  }

  // ---------- search ----------
  function filter(q) {
    q = q.trim().toLowerCase();
    let shown = 0;
    document.querySelectorAll(".case").forEach((sec) => {
      let n = 0;
      sec.querySelectorAll(".row").forEach((r) => {
        const hit = !q || r.dataset.q.includes(q);
        r.hidden = !hit;
        if (hit) n++;
      });
      sec.querySelectorAll(".group").forEach((g) => {
        g.hidden = !!q && !sec.querySelector(`.row[data-group="${CSS.escape(g.dataset.group)}"]:not([hidden])`);
      });
      sec.querySelector(".empty").hidden = n > 0;
      shown += n;
    });
    $("#qCount").textContent = q ? `พบ ${shown} ไฟล์` : "";
  }
  $("#q").addEventListener("input", (e) => filter(e.target.value));

  document.addEventListener("click", (e) => {
    const row = e.target.closest(".row");
    if (row) return openDoc(docsById.get(row.dataset.id));
    const chip = e.target.closest(".chip");
    if (!chip) return;
    const c = manifest.cases.find((x) => x.folder === chip.dataset.case);
    const hits = refsFor(c, chip.dataset.ref);
    if (hits.length === 1) return openDoc(hits[0]);
    $("#q").value = "";
    filter("");
    const els = hits.map((d) => document.querySelector(`.row[data-id="${d.id}"]`)).filter(Boolean);
    if (!els[0]) return;
    els[0].scrollIntoView({ behavior: "smooth", block: "center" });
    els.forEach((el) => { el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); });
  });

  // ---------- viewer ----------
  const viewer = $("#viewer");
  const vBody = $("#vBody");
  const vBar = $("#vProgress");
  let current = null;

  async function fetchDecrypted(doc, token) {
    const res = await fetch(`d/${doc.id}.bin`);
    if (!res.ok) throw new Error("fetch");
    const total = Number(res.headers.get("content-length")) || 0;
    let bytes;
    if (res.body && total) {
      const reader = res.body.getReader();
      bytes = new Uint8Array(total);
      let got = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (token !== current?.token) { reader.cancel(); throw new Error("cancel"); }
        if (got + value.length > bytes.length) { const grown = new Uint8Array(got + value.length); grown.set(bytes); bytes = grown; }
        bytes.set(value, got);
        got += value.length;
        vBar.style.width = Math.min(100, (got / total) * 100) + "%";
      }
      bytes = bytes.slice(0, got);
    } else {
      bytes = new Uint8Array(await res.arrayBuffer());
    }
    vBar.style.width = "100%";
    return new Uint8Array(await unseal(master, bytes));
  }

  async function openDoc(doc) {
    if (!doc) return;
    closeDoc(false);
    const token = Symbol();
    current = { token, zoom: 1 };
    viewer.hidden = false;
    document.body.style.overflow = "hidden";
    history.pushState({ viewer: true }, "");
    $("#vTitle").textContent = (doc.no ? doc.no + " " : "") + doc.title;
    $("#vMeta").textContent = metaOf(doc);
    vBody.innerHTML = `<div class="viewer__state">กำลังเปิดไฟล์ ${fmtSize(doc.size)}…</div>`;
    vBar.style.width = "0";
    const dl = $("#vDownload");
    dl.removeAttribute("href");
    try {
      const data = await fetchDecrypted(doc, token);
      if (token !== current?.token) return;
      current.url = URL.createObjectURL(new Blob([data], { type: doc.mime }));
      dl.href = current.url;
      dl.download = doc.name + extOf(doc.mime);
      if (doc.mime === "application/pdf" && window.pdfjsLib) {
        await renderPdf(data, token);
      } else if (doc.mime === "application/pdf") {
        vBody.innerHTML = `<iframe title="${esc(doc.title)}" src="${current.url}" style="width:100%;height:100%;border:0;background:#fff"></iframe>`;
      } else {
        vBody.innerHTML = `<img class="viewer__img" alt="${esc(doc.title)}" src="${current.url}">`;
        applyZoom();
      }
    } catch (err) {
      if (err.message === "cancel") return;
      vBody.innerHTML = `<div class="viewer__state">เปิดไฟล์ไม่สำเร็จ ตรวจอินเทอร์เน็ตแล้วแตะชื่อไฟล์อีกครั้ง</div>`;
    } finally {
      setTimeout(() => { vBar.style.width = "0"; }, 300);
    }
  }

  async function renderPdf(data, token) {
    const pdf = await pdfjsLib.getDocument({ data, cMapUrl: PDFJS + "cmaps/", cMapPacked: true, standardFontDataUrl: PDFJS + "standard_fonts/" }).promise;
    if (token !== current?.token) return pdf.destroy();
    current.pdf = pdf;
    const first = (await pdf.getPage(1)).getViewport({ scale: 1 });
    const wrap = document.createElement("div");
    wrap.className = "pages";
    for (let n = 1; n <= pdf.numPages; n++) {
      const p = document.createElement("div");
      p.className = "page";
      p.dataset.n = n;
      p.style.aspectRatio = `${first.width} / ${first.height}`;
      p.innerHTML = `<span class="page__no">หน้า ${n} จาก ${pdf.numPages}</span>`;
      wrap.appendChild(p);
    }
    vBody.innerHTML = "";
    vBody.appendChild(wrap);
    applyZoom();
  }

  function applyZoom() {
    if (!current) return;
    const avail = Math.min(vBody.clientWidth - 2 * parseFloat(getComputedStyle(vBody).paddingLeft), 900);
    const w = Math.round(avail * current.zoom);
    const img = vBody.querySelector(".viewer__img");
    if (img) {
      img.style.maxWidth = current.zoom === 1 ? "100%" : "none";
      img.style.width = current.zoom === 1 ? "" : w + "px";
      return;
    }
    if (!current.pdf) return;
    current.observer?.disconnect();
    current.observer = new IntersectionObserver((entries) => {
      entries.forEach((en) => { if (en.isIntersecting) drawPage(en.target); });
    }, { root: vBody, rootMargin: "600px 0px" });
    vBody.querySelectorAll(".page").forEach((p) => {
      p.style.width = current.zoom === 1 ? "min(100%, 900px)" : w + "px";
      p.dataset.drawn = "";
      current.observer.observe(p);
    });
  }

  async function drawPage(el) {
    const cur = current;
    if (!cur?.pdf || el.dataset.drawn === "1") return;
    el.dataset.drawn = "1";
    const page = await cur.pdf.getPage(Number(el.dataset.n));
    const base = page.getViewport({ scale: 1 });
    el.style.aspectRatio = `${base.width} / ${base.height}`;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const vp = page.getViewport({ scale: (el.clientWidth / base.width) * dpr });
    const canvas = document.createElement("canvas");
    canvas.width = Math.floor(vp.width);
    canvas.height = Math.floor(vp.height);
    await page.render({ canvasContext: canvas.getContext("2d"), viewport: vp }).promise;
    if (cur !== current) return;
    el.querySelector("canvas")?.remove();
    el.prepend(canvas);
  }

  function closeDoc(fromButton) {
    if (!current) return;
    current.observer?.disconnect();
    current.pdf?.destroy();
    if (current.url) URL.revokeObjectURL(current.url);
    current = null;
    viewer.hidden = true;
    vBody.innerHTML = "";
    document.body.style.overflow = "";
    if (fromButton === true && history.state?.viewer) history.back();
  }

  const zoomBy = (f) => {
    if (!current) return;
    current.zoom = Math.max(0.5, Math.min(3, Math.round(current.zoom * f * 100) / 100));
    applyZoom();
  };
  $("#vIn").addEventListener("click", () => zoomBy(1.25));
  $("#vOut").addEventListener("click", () => zoomBy(0.8));
  $("#vClose").addEventListener("click", () => closeDoc(true));
  window.addEventListener("popstate", () => closeDoc(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && current) closeDoc(true); });
  let rz;
  window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(applyZoom, 200); });

  boot();
})();
