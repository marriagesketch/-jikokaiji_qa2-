/* ============================================================
   恋活・婚活自己開示QA Part2 – app.js
   ------------------------------------------------------------
   共有リンクは「id（短いランダムID）＋復号鍵（URLのフラグメント）」
   のみで構成される。回答本体は暗号化されたうえで GAS 経由で
   スプレッドシートに保存され、復号鍵はサーバーに送信されない
   （URLの # 以降はブラウザからサーバーへ送信されないため）。
   ============================================================ */

const LIFF_ID   = "2010312230-4V3s95nz";
const DRAFT_KEY = "konkatsu_qa_part2_draft";
const PENDING_SHARED_VIEW_KEY = "konkatsu_qa_part2_pending_shared_view";
// 「クリア」した時刻。これ以前のクラウド下書きは自動復元しない（意図的なクリアを尊重するため）
const DRAFT_CLEARED_AT_KEY = "konkatsu_qa_part2_draft_cleared_at";
// この端末が最後に把握した（保存した／読み込んだ／確認して見送った）クラウド下書きの版（保存時刻）
const DRAFT_SYNCED_AT_KEY = "konkatsu_qa_part2_draft_cloud_synced_at";
// クラウド下書きの暗号鍵導出用（LINEユーザーIDと組み合わせる）。変更すると過去のクラウド下書きは復号できなくなる
const DRAFT_CRYPTO_SALT = "konkatsu_qa_part2_draft_key_v1:";

// ▼▼▼ デプロイ済みGAS Web AppのURL ▼▼▼
const GAS_ENDPOINT = "https://script.google.com/macros/s/AKfycby68Ftif3vL0zULDk0kuP55jsIWCs5EcIFJr_sEz2f4X6NVZTJ4-4wzie04zTbR4TvA/exec";

/* ============================================================
   ワンポイントアドバイス（各質問の下に表示。回答欄ではなく案内文のみ）
   ============================================================ */
const Q_ADVICE = {
  q1:  "なぜそちらを選んだのですか？\n特にタイムスリップしてみたい時代・年代はありますか？",
  q2:  "喧嘩したあとはどうやって仲直りしていましたか？",
  q5:  "それを実現するためにパートナーと協力できそうなことはありますか？",
  q8:  "なぜその使い道を選んだのですか？",
  q9:  "なんでその順番にしたのですか？\nサブスクや趣味などは具体的にどんなものにお金をかけているか聞いてみましょう！",
  q10: "そう感じるようになったきっかけがあれば聞いてみましょう！",
  q12: "なんでその順番にしたのですか？\n具体的に言われたいフレーズはありますか？",
};


/* ============================================================
   Base64URL 変換ユーティリティ（AES鍵・暗号文の符号化に使用）
   ============================================================ */
function bufToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlToBuf(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad    = padded.length % 4;
  const fixed  = pad ? padded + "=".repeat(4 - pad) : padded;
  const binary = atob(fixed);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/* ============================================================
   SHA-256ハッシュ（LINE UserIDのハッシュ化。生IDはサーバーに送らない）
   ============================================================ */
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* ============================================================
   AES-GCM 暗号化ユーティリティ
   鍵はURLのフラグメント（#以降）にのみ含め、サーバーには渡さない。
   ============================================================ */
async function generateShareKey() {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", key);
  return { key, base64: bufToBase64Url(raw) };
}

async function importShareKey(base64) {
  const raw = base64UrlToBuf(base64);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

async function encryptJSON(obj, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);
  const combined = new Uint8Array(iv.length + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), iv.length);
  return bufToBase64Url(combined.buffer);
}

async function decryptJSON(base64, key) {
  const combined = new Uint8Array(base64UrlToBuf(base64));
  const iv   = combined.slice(0, 12);
  const data = combined.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

/* ------------------------------------------------------------
   LINEユーザーIDの取得
   liff.getProfile() はLINEサーバーへの追加API呼び出しが必要で、
   ログイン直後などタイミングによって不安定になりやすい。
   ログイン時に発行されるIDトークンをその場でデコードするだけなら
   通信が発生せず、ユーザーID（sub）を安定して取得できる。
   表示名・プロフィール画像は使わない設計なので、これで十分。
   ------------------------------------------------------------ */
function getLineUserId() {
  const idToken = liff.getDecodedIDToken();
  if (!idToken || !idToken.sub) {
    throw new Error("ID token is not available (sub claim missing)");
  }
  return idToken.sub;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ------------------------------------------------------------
   ランキング選択肢一覧（共有URL短縮のため、テキストの代わりに
   インデックス番号でやり取りする）
   ------------------------------------------------------------ */
const Q9_OPTIONS = [
  "家賃",
  "食費",
  "会社での飲み会代",
  "友人との食事代、飲み会代",
  "旅行代",
  "プレゼント代",
  "衣服や美容にかけるお金",
  "動画配信などのサブスク代",
  "その他趣味に使うお金",
  "その他",
];

const Q11_OPTIONS = [
  "会う頻度、連絡頻度が多い",
  "誉め言葉や感謝の言葉をたくさんくれる",
  "プレゼント",
  "私がお願いしたことを手伝ってくれる",
  "スキンシップ",
];

const Q12_OPTIONS = [
  "容姿の中で、身長や寝起きの顔など生まれつきの要素に関して褒めてくれる",
  "容姿の中で、体型や髪型、服装などある程度自身で変えられるところに関して褒めてくれる",
  "優しい",
  "おもしろい",
  "頭がいい、博識",
  "お店選びや買い物などのセンスがいい",
  "気が利く、思いやりがある",
  "仕事など個人的な努力について褒めてくれる",
  "「作った料理がおいしい」など2人での生活のために頑張ったことについて褒めてくれる",
  "「生きているだけで偉い」のようにとにかく何でも褒めてくれる",
];

/* ------------------------------------------------------------
   ラジオ選択肢ラベル（表示用 & 統計用の全文テキストとして共用）
   ------------------------------------------------------------ */
const Q1_LABELS = {
  "past":   "過去",
  "future": "未来",
};

const Q2_LABELS = {
  "a2-1": "毎日のようにしていた、時々手が出ることもあった",
  "a2-2": "毎日のようにしていたが口喧嘩のみ",
  "a2-3": "たまにしていた、時々手が出ることもあった",
  "a2-4": "たまにしていたが口喧嘩のみ",
  "a2-5": "年に1~2回程度していた",
  "a2-6": "喧嘩した記憶がない、ほとんどない",
};

const Q3_LABELS = {
  "a3-1": "行き当たりばったりがいい",
  "a3-2": "周りの計画に乗っかることが多い",
  "a3-3": "あらかじめ調べて決めておくのが楽しい",
};

const Q4_LABELS = {
  "a4-1": "別行動はしたくない",
  "a4-2": "目の届く範囲内なら良い（たとえば同じフロア内の少し離れた展示を見るなど）",
  "a4-3": "同じ施設内なら目の届かない距離でも良い",
  "a4-4": "数時間以内なら時間を決めて別行動でも構わない",
  "a4-5": "2泊以上の旅行で丸一日別行動の日があっても構わない",
};

const Q8_LABELS = {
  "a8-1": "仕事をやめ(セミFIRE含む) 当選金額で生活する",
  "a8-2": "大きな金額のものを買う",
  "a8-3": "すぐには生活を変えずに貯めておく",
  "a8-4": "寄付する",
};

/* ------------------------------------------------------------
   ランキングUI制御
   各ランキンググループごとに「選択順」を配列で保持する。
   クリック：
     - 未選択 → 末尾に追加し、その順位番号を表示
     - 選択済み → 配列から除去し、それより後ろの順位番号を1つずつ繰り上げる
   ------------------------------------------------------------ */
const rankingState = {
  q9: [],
  q11: [],
  q12: [],
};

function rankingKey(groupId) {
  if (groupId === "q9Ranking")  return "q9";
  if (groupId === "q11Ranking") return "q11";
  if (groupId === "q12Ranking") return "q12";
  return null;
}

function setupRankingGroup(groupId) {
  const group = document.getElementById(groupId);
  if (!group) return;

  const key = rankingKey(groupId);
  if (!key) return;

  group.querySelectorAll(".rank-option").forEach((btn) => {
    btn.addEventListener("click", () => {
      const value = btn.dataset.value;
      const arr   = rankingState[key];
      const idx   = arr.indexOf(value);

      if (idx === -1) {
        arr.push(value);
      } else {
        arr.splice(idx, 1);
      }

      renderRankingGroup(groupId);
    });
  });
}

function renderRankingGroup(groupId) {
  const group = document.getElementById(groupId);
  if (!group) return;

  const key = rankingKey(groupId);
  if (!key) return;
  const arr = rankingState[key];

  group.querySelectorAll(".rank-option").forEach((btn) => {
    const value = btn.dataset.value;
    const order = arr.indexOf(value);
    const numEl = btn.querySelector(".rank-number");

    if (order === -1) {
      btn.classList.remove("selected");
      numEl.textContent = "";
    } else {
      btn.classList.add("selected");
      numEl.textContent = String(order + 1);
    }
  });
}

function resetRankingGroup(groupId) {
  const key = rankingKey(groupId);
  if (!key) return;
  rankingState[key] = [];
  renderRankingGroup(groupId);
}

/* ------------------------------------------------------------
   下書きからのランキング復元
   保存されていた値のうち、現在その選択肢グループに実在する
   data-value のみを採用する（選択肢が変更された場合に順位が
   ずれてしまう不具合を防ぐ）
   ------------------------------------------------------------ */
function restoreRankingGroup(groupId, savedOrder) {
  const key = rankingKey(groupId);
  if (!key) return;

  const group = document.getElementById(groupId);
  const validValues = group
    ? Array.from(group.querySelectorAll(".rank-option")).map(btn => btn.dataset.value)
    : [];

  const filtered = Array.isArray(savedOrder)
    ? savedOrder.filter(v => validValues.includes(v))
    : [];

  rankingState[key] = filtered;
  renderRankingGroup(groupId);
}

/* ------------------------------------------------------------
   フォーム値の収集
   ------------------------------------------------------------ */
function collectFormData() {
  const q1Radio = document.querySelector('input[name="q1"]:checked');
  const q2Radio = document.querySelector('input[name="q2"]:checked');
  const q3Radio = document.querySelector('input[name="q3"]:checked');
  const q4Radio = document.querySelector('input[name="q4"]:checked');
  const q8Radio = document.querySelector('input[name="q8"]:checked');

  return {
    q1:  q1Radio ? q1Radio.value : "",
    q2:  q2Radio ? q2Radio.value : "",
    q3:  q3Radio ? q3Radio.value : "",
    q4:  q4Radio ? q4Radio.value : "",
    q5:  document.getElementById("q5").value,
    q6:  document.getElementById("q6").value,
    q7:  document.getElementById("q7").value,
    q8:  q8Radio ? q8Radio.value : "",
    q9:  rankingState.q9.slice(),
    q10: document.getElementById("q10").value,
    q11: rankingState.q11.slice(),
    q12: rankingState.q12.slice(),
  };
}

/* ------------------------------------------------------------
   フォームへの値の復元
   ------------------------------------------------------------ */
function restoreFormData(data) {
  if (!data) return;

  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el && val !== undefined) el.value = val;
  };

  setText("q5",  data.q5);
  setText("q6",  data.q6);
  setText("q7",  data.q7);
  setText("q10", data.q10);

  if (data.q1) {
    const r = document.querySelector(`input[name="q1"][value="${data.q1}"]`);
    if (r) r.checked = true;
  }
  if (data.q2) {
    const r = document.querySelector(`input[name="q2"][value="${data.q2}"]`);
    if (r) r.checked = true;
  }
  if (data.q3) {
    const r = document.querySelector(`input[name="q3"][value="${data.q3}"]`);
    if (r) r.checked = true;
  }
  if (data.q4) {
    const r = document.querySelector(`input[name="q4"][value="${data.q4}"]`);
    if (r) r.checked = true;
  }
  if (data.q8) {
    const r = document.querySelector(`input[name="q8"][value="${data.q8}"]`);
    if (r) r.checked = true;
  }

  restoreRankingGroup("q9Ranking",  data.q9);
  restoreRankingGroup("q11Ranking", data.q11);
  restoreRankingGroup("q12Ranking", data.q12);
}

/* ------------------------------------------------------------
   フォームの初期化（クリアボタン／クラウド下書きで置き換える時に使用）
   ------------------------------------------------------------ */
function resetFormFields() {
  ["q5","q6","q7","q10"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  document.querySelectorAll('input[type="radio"]').forEach(r => (r.checked = false));
  resetRankingGroup("q9Ranking");
  resetRankingGroup("q11Ranking");
  resetRankingGroup("q12Ranking");
}

/* ============================================================
   下書き：二段構え
   ① 自動保存 … 入力のたびに端末（localStorage）へ保存
   ② 「下書き保存」ボタン … 端末 ＋ クラウド（GAS）へ保存
   端末側のデータが消えても、クラウド側から自動復元する。
   クラウド側は「LINEユーザーID由来の鍵」で暗号化してから送るため、
   サーバー側では内容を読めない（共有リンクと同じ考え方）。
   ============================================================ */

/* 入力が空（初期状態）かどうか。空の状態で既存の下書きを上書きしないために使う */
function isBlankForm(d) {
  if (!d) return true;
  const textKeys  = ["q5","q6","q7","q10"];
  const radioKeys = ["q1","q2","q3","q4","q8"];
  const rankKeys  = ["q9","q11","q12"];
  if (textKeys.some(key => String(d[key] || "").trim() !== "")) return false;
  if (radioKeys.some(key => d[key])) return false;
  if (rankKeys.some(key => Array.isArray(d[key]) && d[key].length > 0)) return false;
  return true;
}

/* ----- 端末（localStorage） ----- */
function readLocalDraft() {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && parsed.v === 2 && parsed.data) {
      return { data: parsed.data, savedAt: Number(parsed.savedAt) || 0 };
    }
    return { data: parsed, savedAt: 0 }; // 旧形式（フォーム値そのまま）との互換
  } catch (e) {
    console.warn("local draft read failed:", e);
    return null;
  }
}

function writeLocalDraft(data, savedAt = Date.now()) {
  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify({ v: 2, savedAt, data }));
    return true;
  } catch (e) {
    console.warn("local draft write failed:", e);
    return false;
  }
}

function getDraftClearedAt() {
  try { return Number(localStorage.getItem(DRAFT_CLEARED_AT_KEY)) || 0; } catch (_) { return 0; }
}
function setDraftClearedAt(ts) {
  try { localStorage.setItem(DRAFT_CLEARED_AT_KEY, String(ts)); } catch (_) {}
}

/* この端末が最後に把握したクラウド下書きの「版」。
   端末ごとの時計のずれに左右されないよう、時刻の大小ではなく
   「別の版かどうか（＝別の端末などで更新されたか）」の判定に使う。 */
function getCloudSyncedAt() {
  try { return Number(localStorage.getItem(DRAFT_SYNCED_AT_KEY)) || 0; } catch (_) { return 0; }
}
function setCloudSyncedAt(ts) {
  try { localStorage.setItem(DRAFT_SYNCED_AT_KEY, String(ts)); } catch (_) {}
}

/* ----- クラウド（GAS） ----- */
function fetchWithTimeout(url, options = {}, ms = 15000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...options, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// 鍵は「ソルト＋LINEユーザーID」のSHA-256。サーバーが持つのはユーザーIDのハッシュ（ownerHash）だけで、
// この鍵は導出できない。
async function getDraftCryptoKey(userId) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(DRAFT_CRYPTO_SALT + userId));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function saveCloudDraft(data, savedAt = Date.now()) {
  const userId     = getLineUserId();
  const ownerHash  = await sha256Hex(userId);
  const key        = await getDraftCryptoKey(userId);
  const cipherText = await encryptJSON(data, key);

  const resp = await fetchWithTimeout(GAS_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" }, // preflight回避
    body: JSON.stringify({ action: "saveDraft", ownerHash, cipherText, savedAt, schemaVersion: 1 }),
  });
  const result = await resp.json();
  if (!result.ok) throw new Error(result.reason || "save_draft_failed");
  setCloudSyncedAt(savedAt); // この端末が保存した版 ＝ 把握済み
  return savedAt;
}

async function loadCloudDraft() {
  const userId    = getLineUserId();
  const ownerHash = await sha256Hex(userId);
  const key       = await getDraftCryptoKey(userId);

  const url  = `${GAS_ENDPOINT}?action=loadDraft&ownerHash=${encodeURIComponent(ownerHash)}`;
  const resp = await fetchWithTimeout(url, { method: "GET" });
  const result = await resp.json();
  if (!result.ok) {
    if (result.reason === "not_found") return null;
    throw new Error(result.reason || "load_draft_failed");
  }
  const data = await decryptJSON(result.cipherText, key);
  return { data, savedAt: Number(result.savedAt) || 0 };
}

/* ----- 起動時：クラウドの下書きを確認して必要なら復元（画面表示はブロックしない） ----- */
async function syncCloudDraft() {
  let cloud;
  try {
    cloud = await loadCloudDraft();
  } catch (e) {
    console.warn("cloud draft load skipped:", e);
    return;
  }
  if (!cloud || isBlankForm(cloud.data)) return;
  if (cloud.savedAt <= getDraftClearedAt()) return; // クリア済み

  const current = collectFormData();

  // 端末側が空（端末のデータが消えた／新しい端末）→ 自動で復元
  if (isBlankForm(current)) {
    resetFormFields();
    restoreFormData(cloud.data);
    writeLocalDraft(cloud.data, cloud.savedAt);
    setCloudSyncedAt(cloud.savedAt);
    return;
  }

  // 端末側にも入力あり。
  // この端末が最後に把握した版と違う（＝別の端末などで更新された）かつ、内容も違う場合だけ確認する
  if (cloud.savedAt === getCloudSyncedAt()) return; // 把握済みの版
  if (JSON.stringify(cloud.data) === JSON.stringify(current)) {
    setCloudSyncedAt(cloud.savedAt); // 内容が同じなら何も聞かず、版だけ揃える
    return;
  }
  const when = cloud.savedAt ? new Date(cloud.savedAt).toLocaleString("ja-JP") : "";
  if (confirm("クラウドに、別の端末などで保存された下書きがあります" + (when ? "（" + when + "）" : "") +
              "。読み込みますか？\n（読み込むと、いま画面にある入力内容は置き換わります）")) {
    resetFormFields();
    restoreFormData(cloud.data);
    writeLocalDraft(cloud.data, cloud.savedAt);
  }
  setCloudSyncedAt(cloud.savedAt); // 読み込んだ場合も、見送った場合も「確認済み」にする
}

/* ----- 送信済みの回答を、自分の下書きとして復元する（共有リンクの所有者のみ） ----- */
async function restoreDraftFromSharedAnswer(sharedData) {
  if (!confirm("この回答を、自分の下書きとして復元します。\n現在保存されている下書きは上書きされます。よろしいですか？")) return;

  const { _shareName, ...formData } = sharedData; // 共有時の表示名は下書きに含めない
  const savedAt = Date.now();
  writeLocalDraft(formData, savedAt);
  try {
    await saveCloudDraft(formData, savedAt);
  } catch (e) {
    console.warn("cloud save during restore failed:", e);
  }
  alert("下書きとして復元しました。回答フォームを開きます。");
  location.href = location.href.split("?")[0].split("#")[0];
}

/* ------------------------------------------------------------
   バリデーション（本送信時のみ）
   ------------------------------------------------------------ */
function validate(data) {
  const errors = [];

  if (!data.q1)        errors.push("Q1: 過去・未来どちらに行きたいか選択してください。");
  if (!data.q2)        errors.push("Q2: 喧嘩の頻度を選択してください。");
  if (!data.q3)        errors.push("Q3: 旅行の計画について選択してください。");
  if (!data.q4)        errors.push("Q4: 旅行中やデート中の別行動について選択してください。");
  if (!data.q5.trim()) errors.push("Q5: 1年後までにしたいことを入力してください。");
  if (!data.q6.trim()) errors.push("Q6: 5年後までにしたいことを入力してください。");
  if (!data.q7.trim()) errors.push("Q7: 定年退職後にしたいことを入力してください。");
  if (!data.q8)        errors.push("Q8: 宝くじ3億円が当たったらどうするか選択してください。");

  const q9Total  = document.querySelectorAll("#q9Ranking .rank-option").length;
  const q11Total = document.querySelectorAll("#q11Ranking .rank-option").length;
  const q12Total = document.querySelectorAll("#q12Ranking .rank-option").length;

  if (data.q9.length  < q9Total)  errors.push("Q9: すべての選択肢を順位付けしてください。");
  if (!data.q10.trim())           errors.push("Q10: 苦手な状況や言動について入力してください。");
  if (data.q11.length < q11Total) errors.push("Q11: すべての選択肢を順位付けしてください。");
  if (data.q12.length < q12Total) errors.push("Q12: すべての選択肢を順位付けしてください。");

  return errors;
}

/* ============================================================
   統計用データの抽出（Analyticsシート行）
   Analyticsシートに列がある項目のみを平文で送る。
   ※ q6（5年後までにしたいこと）は列自体が存在しないため対象外。
   選択式の項目は、集計時にそのまま使えるよう選択肢の全文を入れる。
   ============================================================ */
function buildAnalyticsPayload(data) {
  const rankingText = (arr) => (Array.isArray(arr) && arr.length > 0)
    ? arr.map((v, i) => `${i + 1}位:${v}`).join("、")
    : "";

  return {
    q1:  Q1_LABELS[data.q1] || "",
    q2:  Q2_LABELS[data.q2] || "",
    q3:  Q3_LABELS[data.q3] || "",
    q4:  Q4_LABELS[data.q4] || "",
    q5:  data.q5 || "",
    q7:  data.q7 || "",
    q8:  Q8_LABELS[data.q8] || "",
    q9:  rankingText(data.q9),
    q10: data.q10 || "",
    q11: rankingText(data.q11),
    q12: rankingText(data.q12),
  };
}

/* ============================================================
   フォーム要素を隠す（ビューモード／状態表示に切り替える共通処理）
   ============================================================ */
function hideFormElements() {
  document.querySelectorAll(
    ".container > label, .container > input, .container > textarea, " +
    ".container > div.ranking-group, .container > div.button-group, " +
    ".container > div#shareModal"
  ).forEach(el => (el.style.display = "none"));
}

/* ============================================================
   読み込み中／エラーなどの状態表示（共有リンクを開いたとき用）
   ============================================================ */
function showStateCard(title, text, isLoading = false) {
  hideFormElements();
  const container = document.getElementById("viewMode");
  container.style.display = "block";
  container.innerHTML = `
    <div class="view-header state-card">
      ${isLoading ? `
        <div class="state-spinner">
          <img src="https://developers.line.biz/media/line-mini-app/LINE_spinner_light.svg" class="spinner-light" alt="読み込み中">
          <img src="https://developers.line.biz/media/line-mini-app/LINE_spinner_dark.svg" class="spinner-dark" alt="読み込み中">
        </div>
      ` : ""}
      <p class="view-label">${escapeHTML(title)}</p>
      <p class="state-text">${escapeHTML(text)}</p>
    </div>
  `;
}

/* ============================================================
   共有リンクを開いたときの処理
   ・URLの ?id=... がスプレッドシート上のレコードを指す
   ・URLの #以降 が復号鍵（サーバーには送信されない）
   ・閲覧にはLINEログインが必須（viewerHashによるアクセス制御のため）
   ============================================================ */
async function handleSharedView(id) {
  // ここに来た時点で liff.init() は完了済み（呼び出し元のメイン処理を参照）。
  // 直後にログインリダイレクトが必要な場合は isLoggedIn() が false になるため
  // その場合はログインへ送り、リダイレクト復帰後に改めてこの関数が呼ばれる。
  showStateCard("読み込み中…", "回答内容を確認しています。少々お待ちください。", true);

  const keyBase64 = location.hash ? location.hash.slice(1) : "";
  if (!keyBase64) {
    showStateCard(
      "リンクが不完全です",
      "共有リンクが途中で切れているか、正しくコピーされていない可能性があります。共有した相手にもう一度リンクを送ってもらってください。"
    );
    return;
  }

  if (!liff.isLoggedIn()) {
    // LINEログイン画面へ遷移する前に、共有リンク情報（id・復号鍵）を
    // sessionStorageへ退避しておく。ログイン往復後にURLの
    // ?id=...#鍵 が正しく復元されないブラウザ・状況があり、その場合に
    // 自分の回答フォーム側へ誤って遷移してしまう不具合の対策。
    try {
      sessionStorage.setItem(PENDING_SHARED_VIEW_KEY, location.href);
    } catch (_) {}
    liff.login();
    return;
  }

  let key;
  try {
    key = await importShareKey(keyBase64);
  } catch (e) {
    console.error("key import error", e);
    showStateCard("リンクが正しくありません", "共有リンクが壊れている可能性があります。");
    return;
  }

  let viewerHash;
  try {
    const userId = getLineUserId();
    viewerHash = await sha256Hex(userId);
  } catch (e) {
    console.error("get user id error", e);
    showStateCard(
      "エラー",
      "LINEアカウント情報の確認に失敗しました。時間をおいてもう一度お試しください。" +
      "（詳細: " + (e && e.message ? e.message : String(e)) + "）"
    );
    return;
  }

  let result;
  try {
    const url = `${GAS_ENDPOINT}?action=view&id=${encodeURIComponent(id)}&viewerHash=${encodeURIComponent(viewerHash)}`;
    const resp = await fetch(url, { method: "GET" });
    result = await resp.json();
  } catch (e) {
    console.error("fetch view error", e);
    showStateCard("通信エラー", "回答内容を取得できませんでした。通信環境を確認してもう一度お試しください。");
    return;
  }

  if (!result.ok) {
    if (result.reason === "forbidden") {
      showStateCard(
        "閲覧できません",
        "このリンクは最初に開いた方専用です。転送されたリンクは、その方以外は閲覧できない仕組みになっています。"
      );
    } else if (result.reason === "revoked" || result.reason === "expired" || result.reason === "deleted") {
      showStateCard("リンクが無効です", "このリンクはすでに無効になっています。最新の共有リンクを送ってもらってください。");
    } else if (result.reason === "not_found") {
      showStateCard("リンクが見つかりません", "このリンクは存在しないか、削除された可能性があります。");
    } else {
      showStateCard("エラー", "回答内容を取得できませんでした。時間をおいて再度お試しください。");
    }
    return;
  }

  let data;
  try {
    data = await decryptJSON(result.cipherText, key);
  } catch (e) {
    console.error("decrypt error", e);
    showStateCard("復号に失敗しました", "リンクの一部が正しくない可能性があります。共有した相手にもう一度リンクを送ってもらってください。");
    return;
  }

  // GAS側が isOwner: true を返した場合（閲覧者＝共有を作成した本人）のみ、下書き復元ボタンを出す
  renderViewMode(data, result.isOwner === true
    ? { onRestoreDraft: () => restoreDraftFromSharedAnswer(data) }
    : {});
  showScreenshotWatermark(viewerHash);
}

/* ------------------------------------------------------------
   ランキング配列 → 「1位：◯◯」形式のHTML（昇順）
   ------------------------------------------------------------ */
function rankingListHTML(arr) {
  if (!Array.isArray(arr) || arr.length === 0) return "未回答";

  return arr
    .map((item, i) => `${i + 1}位：${escapeHTML(item)}`)
    .join("<br>");
}

/* ------------------------------------------------------------
   ビューモード：回答をカード表示
   ------------------------------------------------------------ */
function renderViewMode(data, options = {}) {
  const { selfPreview = false, onShare = null, onRestoreDraft = null } = options;

  const q1Labels = Q1_LABELS;
  const q2Labels = Q2_LABELS;
  const q3Labels = Q3_LABELS;
  const q4Labels = Q4_LABELS;
  const q8Labels = Q8_LABELS;

  const rows = [
    { q: "Q1 タイムスリップができるなら過去と未来どちらに行きたいですか？",
      a: q1Labels[data.q1] || "未回答", tip: Q_ADVICE.q1 },
    { q: "Q2 子どもの頃、兄弟げんかや親子げんかはする方でしたか？",
      a: q2Labels[data.q2] || "未回答", tip: Q_ADVICE.q2 },
    { q: "Q3 旅行は計画立てて行くのが好きですか？行き当たりばったりがいいですか？",
      a: q3Labels[data.q3] || "未回答", tip: Q_ADVICE.q3 },
    { q: "Q4 旅行中やデート中の別行動はしても平気なタイプですか？",
      a: q4Labels[data.q4] || "未回答", tip: Q_ADVICE.q4 },
    { q: "Q5 1年後までに個人的にしたいことはありますか？", a: data.q5 || "未回答", tip: Q_ADVICE.q5 },
    { q: "Q6 5年後までに個人的にしたいことはありますか？", a: data.q6 || "未回答", tip: Q_ADVICE.q6 },
    { q: "Q7 定年退職後ぐらいの年齢で個人的にしたいことはありますか？", a: data.q7 || "未回答", tip: Q_ADVICE.q7 },
    { q: "Q8 もし宝くじ3億円が当たったらどうしますか？",
      a: q8Labels[data.q8] || "未回答", tip: Q_ADVICE.q8 },
    { q: "Q9 業績不振により給料が減ることになった場合、支出を削ってもいいと思う順番",
      html: rankingListHTML(data.q9), tip: Q_ADVICE.q9 },
    { q: "Q10 これだけは苦手または生理的に受け付けないというシチュエーションや他人の言動はありますか？",
      a: data.q10 || "未回答", tip: Q_ADVICE.q10 },
    { q: "Q11 次の愛情表現について、嬉しい順",
      html: rankingListHTML(data.q11), tip: Q_ADVICE.q11 },
    { q: "Q12 デートや日常生活のなかでパートナーからなんて褒められるのが嬉しいですか？",
      html: rankingListHTML(data.q12), tip: Q_ADVICE.q12 },
  ];

  hideFormElements();

  // 自分自身（このLIFFアプリ）の回答フォームURL
  const formURL = location.href.split("?")[0].split("#")[0];

  // 共有画面（ビューモード）の上部注意書きを差し替える
  const descEl = document.querySelector(".form-header .form-description");
  if (descEl) {
    descEl.innerHTML =
      "回答を共有してお互いのことを知りましょう。<br>" +
      "回答内容だけじゃなく、なぜそう思ってるのか、この場合はどう変わるかなども質問し合ってみましょう。";
  }

  const container = document.getElementById("viewMode");
  container.style.display = "block";
  container.innerHTML = `
    ${selfPreview ? `
    <div class="cta-card share-confirm-card">
      <div class="cta-content" style="text-align:center;">
        <h3 class="cta-title">この内容を共有します</h3>
        <p class="cta-text">
          内容を確認したら、共有先を選んでください。
        </p>
        <button type="button" id="goShareBtn" class="cta-button">
          共有先を選ぶ <span class="cta-arrow">›</span>
        </button>
      </div>
    </div>
    ` : ""}

    ${!selfPreview ? `
    <div class="view-header">
      <p class="view-label">回答内容</p>
      ${data._shareName ? `<p class="view-name">${escapeHTML(data._shareName)} さんの回答</p>` : ""}
    </div>
    ` : ""}

    ${(!selfPreview && onRestoreDraft) ? `
    <div class="cta-card share-confirm-card">
      <div class="cta-content" style="text-align:center;">
        <h3 class="cta-title">あなたが送信した回答です</h3>
        <p class="cta-text">
          この回答を、自分の下書きとして復元できます。
        </p>
        <button type="button" id="restoreDraftBtn" class="cta-button">
          下書きとして復元する <span class="cta-arrow">›</span>
        </button>
      </div>
    </div>
    ` : ""}

    ${rows.map(({ q, a, html, tip }) => `
      <div class="view-item">
        <p class="view-question">${escapeHTML(q)}</p>
        <p class="view-answer">${html ? html : escapeHTML(a).replace(/\n/g, "<br>")}</p>
        ${tip ? `
        <div class="view-tip">
          <span class="view-tip-icon">💡</span>
          <p class="view-tip-text"><strong>あわせて聞いてみましょう：</strong><br>${escapeHTML(tip).replace(/\n/g, "<br>")}</p>
        </div>
        ` : ""}
      </div>
    `).join("")}

    ${!selfPreview ? `
    <div class="cta-card">
      <img src="shareimage.webp" class="cta-image-left" alt="">
      <div class="cta-content">
        <h3 class="cta-title">あなたの価値観も共有してみませんか？</h3>
        <p class="cta-text">
          交際前・交際中の自己開示は、<br>
          お互いを知る大切なきっかけになります。<br>
          あなたの考えや価値観をアンケートで伝えてみましょう。
        </p>
        <button type="button" id="ctaButton" class="cta-button" data-href="${formURL}">
          私も回答する <span class="cta-arrow">›</span>
        </button>
      </div>
    </div>
    ` : ""}
  `;

  if (selfPreview) {
    const goShareBtn = document.getElementById("goShareBtn");
    if (goShareBtn && typeof onShare === "function") {
      goShareBtn.addEventListener("click", onShare);
    }
    return;
  }

  const restoreDraftBtn = document.getElementById("restoreDraftBtn");
  if (restoreDraftBtn && typeof onRestoreDraft === "function") {
    restoreDraftBtn.addEventListener("click", onRestoreDraft);
  }

  const ctaButton = document.getElementById("ctaButton");
  if (ctaButton) {
    ctaButton.addEventListener("click", () => {
      if (confirm("自己開示QA part2を開く")) {
        window.location.href = ctaButton.dataset.href;
      }
    });
  }
}

/* ------------------------------------------------------------
   LINEユーザーIDの取得
   liff.getProfile() はLINEサーバーへの追加API呼び出しが必要で、
   ログイン直後などタイミングによって不安定になりやすい。
   ログイン時に発行されるIDトークンをその場でデコードするだけなら
   通信が発生せず、ユーザーID（sub）を安定して取得できる。
   表示名・プロフィール画像は使わない設計なので、これで十分。
   ------------------------------------------------------------ */
function getLineUserId() {
  const idToken = liff.getDecodedIDToken();
  if (!idToken || !idToken.sub) {
    throw new Error("ID token is not available (sub claim missing)");
  }
  return idToken.sub;
}

/* ------------------------------------------------------------
   スクショ抑止用ウォーターマーク
   ------------------------------------------------------------
   Webアプリの仕様上、スクリーンショットの撮影自体を検知・
   ブロックすることはできない。そのため「撮られても、誰が・いつ
   閲覧した画面かが写り込む」ようにし、無断転載・拡散への
   心理的な抑止力として機能させる。
   閲覧者のLINEユーザーIDハッシュ（先頭8文字）と閲覧日時を、
   画面全体に薄く敷き詰めて表示する。position:fixedのため
   スクロールしても常に画面上に留まる。
   ------------------------------------------------------------ */
function buildWatermarkSVG(lines) {
  const tileW = 240, tileH = 140;
  const lineHeight = 16;
  const startY = tileH / 2 - ((lines.length - 1) * lineHeight) / 2;

  const textEls = lines.map((line, i) => {
    const y = startY + i * lineHeight;
    return `<text x="0" y="${y}" font-size="12" font-family="sans-serif" ` +
           `fill="rgba(0,0,0,0.1)" transform="rotate(-28 ${tileW / 2} ${tileH / 2})">${escapeHTML(line)}</text>`;
  }).join("");

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${tileW}" height="${tileH}">${textEls}</svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

function showScreenshotWatermark(viewerHash) {
  const el = document.getElementById("screenshotWatermark");
  if (!el) return;
  const stamp = new Date().toLocaleString("ja-JP", {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
  const lines = [
    "スクショ・転載禁止",
    `${viewerHash.slice(0, 8)}  ${stamp}`,
  ];
  el.style.backgroundImage = `url("${buildWatermarkSVG(lines)}")`;
  el.classList.add("show");
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ------------------------------------------------------------
   共有：シェアターゲットピッカー用 Flexメッセージ
   長い共有URLはボタン(uriアクション)の中に格納するため、
   相手に見える本文には長いリンクが表示されない。
   ※ uriアクションのURLは1000文字以内という制限があるため、
     超える場合は liff.shareTargetPicker 側でエラーになり、
     呼び出し元で従来のURLスキーム方式にフォールバックする。
   ※ hero画像のURLは、LINEのサーバーから読み込める公開HTTPS URL
     である必要がある（ローカルパスや相対パスは不可）。
     画像は1MB以下を推奨。webpの透過部分はそのまま送ると
     反映されない場合があるため、白背景に合成したJPEGを使用する。
   ------------------------------------------------------------ */
const SHARETARGETPICKER_IMAGE_URL = "https://marriagesketch.github.io/-jikokaiji_qa2-/sharetargetpicker.jpg"; 

function buildShareFlexMessage(shareName, shareURL) {
  const nameLine = shareName ? `${shareName}さんの回答が届きました` : "回答が届きました";

  return {
    type: "flex",
    altText: `恋活・婚活 自己開示QA Part2 - ${nameLine}`,
    contents: {
      type: "bubble",
      hero: {
        type: "image",
        url: SHARETARGETPICKER_IMAGE_URL,
        size: "full",
        aspectRatio: "3:2",
        aspectMode: "cover"
      },
      body: {
        type: "box",
        layout: "vertical",
        spacing: "md",
        paddingAll: "20px",
        contents: [
          { type: "text", text: "恋活・婚活 自己開示QA Part2", size: "xs", weight: "bold", color: "#d96c7d" },
          { type: "text", text: nameLine, size: "lg", weight: "bold", wrap: true, margin: "sm" },
          { type: "text", text: "ボタンから回答内容を確認できます。", size: "sm", color: "#888888", wrap: true, margin: "md" }
        ]
      },
      footer: {
        type: "box",
        layout: "vertical",
        spacing: "sm",
        paddingAll: "20px",
        contents: [
          {
            type: "button",
            style: "primary",
            height: "sm",
            color: "#f48ca0",
            action: { type: "uri", label: "回答をみる", uri: shareURL }
          }
        ]
      }
    }
  };
}

/* ------------------------------------------------------------
   共有先を選んで送信する
   1. シェアターゲットピッカーが使える場合はそちらを優先
      （Flexメッセージとして直接送信、送信後にトーク画面へ遷移しない）
   2. 使えない・失敗した場合は、従来のURLスキーム方式（送信先を
      選択画面を開いてテキストメッセージを送る）にフォールバック
   ------------------------------------------------------------ */
async function shareToOthers(flexMessage, fallbackLineSchemeURL) {
  if (liff.isApiAvailable("shareTargetPicker")) {
    try {
      await liff.shareTargetPicker([flexMessage], { isMultiple: true });
      return;
    } catch (e) {
      console.warn("shareTargetPicker failed, falling back to URL scheme:", e);
    }
  }

  if (liff.isInClient()) {
    window.location.href = fallbackLineSchemeURL;
  } else {
    window.open(fallbackLineSchemeURL, "_blank");
  }
}

/* ------------------------------------------------------------
   友だち追加チェック
   LINE公式アカウントを友だち追加済みかを確認し、未追加であれば
   友だち追加ダイアログを表示する。
   ※ LIFF初期化・ログイン済みの状態で呼び出すこと（liff.init は呼ばない）
   ------------------------------------------------------------ */
async function checkFriendship() {
  try {
    const friendship = await liff.getFriendship();
    if (!friendship.friendFlag) {
      try {
        await liff.requestFriendship();
      } catch (error) {
        console.warn("友だち追加リクエスト失敗（ユーザーがキャンセルした可能性があります）:", error);
      }
    }
  } catch (error) {
    console.warn("友だち確認をスキップ:", error);
  }
}

/* ------------------------------------------------------------
   メイン処理
   ------------------------------------------------------------ */
(async () => {

  /* ----- LIFF 初期化（必ず最初に1回だけ実行） -----
     共有リンク判定に使うURL（?id=...#key）の読み取りは、
     必ずこの後で行う。ログインのリダイレクトを経由して
     戻ってきた直後は、URLが一時的に ?liff.state=... の形に
     なっていて ?id=... が正しく読み取れないことがあるため。
     （このケースはLINEログイン確認が必要な場合のみ発生し、
     　通常はセッションが有効なため即座に初期化が完了する）
  ----- */
  try {
    await liff.init({ liffId: LIFF_ID });
  } catch (e) {
    console.error("LIFF init failed", e);
    alert(
      "LIFFの初期化に失敗しました。\n\n" +
      "[デバッグ情報]\n" +
      "code: " + (e && e.code) + "\n" +
      "message: " + (e && e.message)
    );
    return;
  }

  /* ----- 共有リンク判定（?id=... が付いている場合） ----- */
  /* ----- 共有リンク判定（?id=... が付いている場合） -----
     LINEログインへのリダイレクトを経由した直後は、ブラウザや状況に
     よってURLの ?id=...#鍵 が正しく復元されないことがある。その場合は
     handleSharedView側でliff.login()前にsessionStorageへ退避しておいた
     URLから復元する（フォールバック）。 */
  let sharedId = new URLSearchParams(location.search).get("id");
  if (!sharedId) {
    try {
      const pending = sessionStorage.getItem(PENDING_SHARED_VIEW_KEY);
      if (pending) {
        const pendingURL = new URL(pending);
        const pendingId = new URLSearchParams(pendingURL.search).get("id");
        if (pendingId) {
          sharedId = pendingId;
          const restoredHash = location.hash || pendingURL.hash;
          history.replaceState(null, "", location.pathname + pendingURL.search + restoredHash);
        }
      }
    } catch (_) {}
  }
  try { sessionStorage.removeItem(PENDING_SHARED_VIEW_KEY); } catch (_) {}

  if (sharedId) {
    await handleSharedView(sharedId);
    return;
  }

  if (!liff.isLoggedIn()) {
    liff.login();
    return;
  }

  /* ----- 友だち追加チェック（未追加なら追加ダイアログを表示） -----
     liff.getFriendship() / requestFriendship() はLINEサーバーへの通信を
     伴うため、ここをawaitすると電波が悪い時に画面表示自体が止まって
     しまう。必須の処理ではないので、裏側で実行させて画面構築は
     先に進める（fire-and-forget）。 */
  checkFriendship();

  /* ----- ランキングUIの初期化 ----- */
  setupRankingGroup("q9Ranking");
  setupRankingGroup("q11Ranking");
  setupRankingGroup("q12Ranking");

  /* ----- 下書き復元：①端末（localStorage）→ ②クラウド（裏で確認） ----- */
  const localDraft = readLocalDraft();
  if (localDraft) {
    try {
      restoreFormData(localDraft.data);
    } catch (e) {
      console.warn("local draft restore failed:", e);
    }
  }

  /* ----- 自動保存（端末）-----
     入力のたびに（0.5秒まとめて）端末へ保存。画面を離れる／アプリが
     バックグラウンドに回る時にも即時保存する。
     入力が空の状態では保存しない（既存の下書きを空で上書きしないため）。 */
  let autosaveTimer = null;
  const flushAutosave = () => {
    clearTimeout(autosaveTimer);
    autosaveTimer = null;
    const data = collectFormData();
    if (isBlankForm(data)) return;
    const saved = readLocalDraft();
    if (saved && JSON.stringify(saved.data) === JSON.stringify(data)) return; // 変更なし → 保存時刻は更新しない
    writeLocalDraft(data);
  };
  const scheduleAutosave = (e) => {
    if (e && e.target && e.target.closest && e.target.closest("#shareModal")) return;
    clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(flushAutosave, 500);
  };
  document.addEventListener("input", scheduleAutosave);
  document.addEventListener("change", scheduleAutosave);
  // ランキングUIは input/change が発火しない独自ボタンなので、クリックでも自動保存を予約する
  document.addEventListener("click", (e) => {
    if (e.target && e.target.closest && e.target.closest(".rank-option")) scheduleAutosave(e);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") flushAutosave();
  });
  window.addEventListener("pagehide", flushAutosave);

  /* ----- クラウドの下書きを確認（裏で実行。画面表示は止めない） ----- */
  syncCloudDraft();

  /* ----- 下書き保存（端末 ＋ クラウド） ----- */
  document.getElementById("draftBtn").addEventListener("click", async () => {
    const draftBtn = document.getElementById("draftBtn");
    const data = collectFormData();
    if (isBlankForm(data)) {
      alert("入力内容がまだありません。");
      return;
    }

    const savedAt = Date.now();
    const localOk = writeLocalDraft(data, savedAt);

    const originalLabel = draftBtn.textContent;
    draftBtn.disabled = true;
    draftBtn.textContent = "保存中…";
    try {
      await saveCloudDraft(data, savedAt);
      alert(localOk
        ? "下書きを保存しました。\n（この端末とクラウドの両方に保存されています）"
        : "クラウドに下書きを保存しました。\n（この端末への保存は失敗しました）");
    } catch (e) {
      console.warn("cloud draft save failed:", e);
      alert(localOk
        ? "この端末には保存しましたが、クラウドへの保存に失敗しました。\n通信環境を確認して、もう一度お試しください。"
        : "下書きの保存に失敗しました。通信環境を確認して、もう一度お試しください。");
    } finally {
      draftBtn.disabled = false;
      draftBtn.textContent = originalLabel;
    }
  });

  /* ----- フォームクリア ----- */
  document.getElementById("clearBtn").addEventListener("click", () => {
    if (!confirm("入力内容をすべてクリアしますか？")) return;
    clearTimeout(autosaveTimer);
    resetFormFields();
    try { localStorage.removeItem(DRAFT_KEY); } catch (_) {}
    // 意図的なクリア。これ以前に保存したクラウド下書きは、次回起動時に自動復元しない
    setDraftClearedAt(Date.now());
  });

  /* ----- 送信ボタン ----- */
  document.getElementById("submitBtn").addEventListener("click", () => {
    const data   = collectFormData();
    const errors = validate(data);

    if (errors.length > 0) {
      alert("以下の項目を入力してください。\n\n" + errors.join("\n"));
      return;
    }

    // 前回の回答として保存（次回編集時に復元できるようにする）
    writeLocalDraft(data);

    const modal = document.getElementById("shareModal");
    modal.classList.remove("hidden");
    modal.classList.add("show");

    document.getElementById("submitBtn").disabled = true;
  });

  /* ----- 共有ボタン ----- */
  document.getElementById("shareBtn").addEventListener("click", async () => {
    const shareBtn   = document.getElementById("shareBtn");
    const shareName  = document.getElementById("shareName").value.trim();
    const formData  = collectFormData();
    const data      = { ...formData, _shareName: shareName };

    shareBtn.disabled = true;
    const originalLabel = shareBtn.textContent;
    shareBtn.textContent = "送信中…";

    try {
      const userId    = getLineUserId();
      const ownerHash = await sha256Hex(userId);

      const id = (crypto.randomUUID ? crypto.randomUUID() : fallbackUUID());
      const { key, base64: keyBase64 } = await generateShareKey();
      const cipherText = await encryptJSON(data, key);
      const analytics  = buildAnalyticsPayload(data);

      const resp = await fetch(GAS_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=utf-8" }, // preflight回避のため text/plain を使用
        body: JSON.stringify({ action: "share", id, cipherText, ownerHash, analytics, schemaVersion: 1 }),
      });
      const result = await resp.json();
      if (!result.ok) throw new Error(result.reason || "share_failed");

      // 共有に成功した回答を、クラウドの下書きにも保存しておく（失敗しても共有処理は止めない）。
      // 端末のデータが消えても、送信済みの回答を下書きとして復元できるようにするため。
      saveCloudDraft(formData).catch(e => console.warn("cloud draft save after share failed:", e));

      const base     = location.href.split("?")[0].split("#")[0];
      const shareURL = `${base}?id=${id}#${keyBase64}`;

      const previewMsg = shareName
        ? `${shareName}さんの恋活・婚活　自己開示QA part2の回答が届きました。\n回答をみる→${shareURL}`
        : `恋活・婚活　自己開示QA part2の回答が届きました。\n回答をみる→${shareURL}`;

      const flexMessage = buildShareFlexMessage(shareName, shareURL);

      // モーダルを閉じる
      const modal = document.getElementById("shareModal");
      modal.classList.remove("show");
      modal.classList.add("hidden");

      // まず本人の画面を「回答内容」プレビューに切り替える
      renderViewMode(data, {
        selfPreview: true,
        onShare: () => {
          const lineShareURL = `https://line.me/R/msg/text/?${encodeURIComponent(previewMsg)}`;
          shareToOthers(flexMessage, lineShareURL);
        },
      });

      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (e) {
      console.error("share error", e);
      alert("共有の準備に失敗しました。通信環境を確認してもう一度お試しください。");
      document.getElementById("submitBtn").disabled = false;
    } finally {
      shareBtn.disabled = false;
      shareBtn.textContent = originalLabel;
    }
  });

  /* ----- モーダル外クリックで閉じる ----- */
  document.getElementById("shareModal").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) {
      e.currentTarget.classList.remove("show");
      e.currentTarget.classList.add("hidden");
    }
  });

})();

/* crypto.randomUUID が使えない古い環境用のフォールバック */
function fallbackUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
