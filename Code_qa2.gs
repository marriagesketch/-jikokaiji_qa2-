/* ============================================================
   婚活自己開示QA Part2 – GAS バックエンド (Code.gs)
   スプレッドシートID: 1Iv6Ozch7ULP6WGb48zqlKgpLV6ILyDzledcAsZ32x_0
   ------------------------------------------------------------
   ・Shares    シート : 共有用の暗号化済み回答（本人／初回閲覧者のみ復号可）
   ・Analytics シート : 統計集計に必要な項目のみを平文で保存
   ------------------------------------------------------------
   デプロイ方法:
   1. スプレッドシートを開き「拡張機能 > Apps Script」でこのコードを貼り付ける。
   2. 「デプロイ > 新しいデプロイ」→ 種類「ウェブアプリ」
      - 実行するユーザー: 自分
      - アクセスできるユーザー: 全員
      でデプロイする（すでに発行済みの /exec URL を app.js の
      GAS_ENDPOINT に設定済み）。
   ============================================================ */

var SPREADSHEET_ID  = '1Iv6Ozch7ULP6WGb48zqlKgpLV6ILyDzledcAsZ32x_0';
var SHARES_SHEET     = 'Shares';
var ANALYTICS_SHEET  = 'Analytics';
var SCHEMA_VERSION   = 1;

// Shares シートの列番号（1-indexed）
var COL = {
  ID: 1, CIPHER_TEXT: 2, ENCRYPTED_KEY: 3, OWNER_HASH: 4, VIEWER_HASH: 5,
  STATUS: 6, SCHEMA_VERSION: 7, CREATED_AT: 8, UPDATED_AT: 9,
  FIRST_VIEWED_AT: 10, LAST_VIEWED_AT: 11, VIEW_COUNT: 12
};

// Analytics シートの列番号（1-indexed）
// ※ q6（5年後までにしたいこと）はスプレッドシートに列自体が存在しない
//   ため現状は書き込んでいません（他の自由記述q5/q7/q10は列があるため
//   含めています。意図的な除外でなければ列を追加してください）。
var ACOL = {
  ID: 1, OWNER_HASH: 2, VIEWER_HASH: 3, CREATED_AT: 4,
  Q1: 5, Q2: 6, Q3: 7, Q4: 8, Q5: 9, Q7: 10, Q8: 11, Q9: 12, Q10: 13, Q11: 14, Q12: 15
};

var DATA_START_ROW = 2; // 1行目=見出し, 2行目以降がデータ


/* ------------------------------------------------------------
   エントリポイント
   ------------------------------------------------------------ */
function doGet(e) {
  try {
    var action = e.parameter.action;
    if (action === 'view') {
      return handleView(e.parameter.id, e.parameter.viewerHash);
    }
    return jsonResponse({ ok: false, reason: 'invalid_action' });
  } catch (err) {
    return jsonResponse({ ok: false, reason: 'server_error', message: String(err) });
  }
}

function doPost(e) {
  try {
    var body = JSON.parse(e.postData.contents);
    if (body.action === 'share') {
      return handleShare(body);
    }
    return jsonResponse({ ok: false, reason: 'invalid_action' });
  } catch (err) {
    return jsonResponse({ ok: false, reason: 'server_error', message: String(err) });
  }
}

function jsonResponse(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function getSpreadsheet() {
  return SpreadsheetApp.openById(SPREADSHEET_ID);
}


/* ------------------------------------------------------------
   共有登録（回答の保存）
   ・cipherText はクライアント側で AES-GCM 暗号化済みのため、
     このサーバー（および管理者）は復号鍵を一切受け取らない。
   ・同じ ownerHash（同一LINEアカウント）から再度共有された場合、
     Shares・Analytics いずれも以前の行を削除したうえで新しい行を
     追加する（＝完全上書き。1人1行に統一される）。
   ------------------------------------------------------------ */
function handleShare(body) {
  var id         = body.id;
  var cipherText = body.cipherText;
  var ownerHash  = body.ownerHash;
  var analytics  = body.analytics || {};

  if (!id || !cipherText || !ownerHash) {
    return jsonResponse({ ok: false, reason: 'invalid_params' });
  }

  var lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    var ss = getSpreadsheet();
    var sharesSheet    = ss.getSheetByName(SHARES_SHEET);
    var analyticsSheet = ss.getSheetByName(ANALYTICS_SHEET);
    var now = new Date();

    removePreviousShares(sharesSheet, ownerHash);
    removePreviousAnalytics(analyticsSheet, ownerHash);

    sharesSheet.appendRow([
      id, cipherText, '', ownerHash, '', 'active', SCHEMA_VERSION,
      now, now, '', '', 0
    ]);

    analyticsSheet.appendRow([
      id, ownerHash, '', now,
      analytics.q1 || '', analytics.q2 || '', analytics.q3 || '', analytics.q4 || '',
      analytics.q5 || '', analytics.q7 || '', analytics.q8 || '',
      analytics.q9 || '', analytics.q10 || '', analytics.q11 || '', analytics.q12 || ''
    ]);

    return jsonResponse({ ok: true, id: id });
  } finally {
    lock.releaseLock();
  }
}

/* 同じ ownerHash の既存 Shares 行を削除する（完全上書き・1人1行に統一） */
function removePreviousShares(sheet, ownerHash) {
  var lastRow = sheet.getLastRow();
  if (lastRow < DATA_START_ROW) return;
  var values = sheet.getRange(DATA_START_ROW, 1, lastRow - DATA_START_ROW + 1, COL.OWNER_HASH).getValues();
  for (var i = values.length - 1; i >= 0; i--) {
    if (values[i][COL.OWNER_HASH - 1] === ownerHash) {
      sheet.deleteRow(DATA_START_ROW + i);
    }
  }
}

/* 同じ ownerHash の既存 Analytics 行を削除する（完全上書き・1人1行に統一） */
function removePreviousAnalytics(sheet, ownerHash) {
  var lastRow = sheet.getLastRow();
  if (lastRow < DATA_START_ROW) return;
  var values = sheet.getRange(DATA_START_ROW, 1, lastRow - DATA_START_ROW + 1, ACOL.OWNER_HASH).getValues();
  for (var i = values.length - 1; i >= 0; i--) {
    if (values[i][ACOL.OWNER_HASH - 1] === ownerHash) {
      sheet.deleteRow(DATA_START_ROW + i);
    }
  }
}


/* ------------------------------------------------------------
   閲覧（共有リンクを開いたとき）
   アクセス制御:
   ・本人（ownerHash と一致） → 常に許可
   ・viewerHash が未登録      → この人を初回閲覧者として登録し許可
   ・viewerHash が登録済み    → 一致すれば許可、不一致なら拒否
   ------------------------------------------------------------ */
function handleView(id, viewerHash) {
  if (!id) return jsonResponse({ ok: false, reason: 'invalid_params' });
  if (!viewerHash) return jsonResponse({ ok: false, reason: 'login_required' });

  var lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    var sheet = getSpreadsheet().getSheetByName(SHARES_SHEET);
    var rowIndex = findRowById(sheet, id);
    if (!rowIndex) return jsonResponse({ ok: false, reason: 'not_found' });

    var row = sheet.getRange(rowIndex, 1, 1, COL.VIEW_COUNT).getValues()[0];
    var cipherText         = row[COL.CIPHER_TEXT - 1];
    var ownerHash           = row[COL.OWNER_HASH - 1];
    var existingViewerHash  = row[COL.VIEWER_HASH - 1];
    var status              = row[COL.STATUS - 1];

    if (status !== 'active') {
      return jsonResponse({ ok: false, reason: status === 'active' ? 'not_found' : status });
    }

    var now = new Date();
    var allowed = false;

    if (viewerHash === ownerHash) {
      allowed = true;
    } else if (!existingViewerHash) {
      allowed = true;
      sheet.getRange(rowIndex, COL.VIEWER_HASH).setValue(viewerHash);
      sheet.getRange(rowIndex, COL.FIRST_VIEWED_AT).setValue(now);
      updateAnalyticsViewerHash(id, viewerHash);
    } else if (existingViewerHash === viewerHash) {
      allowed = true;
    } else {
      allowed = false;
    }

    if (!allowed) return jsonResponse({ ok: false, reason: 'forbidden' });

    sheet.getRange(rowIndex, COL.LAST_VIEWED_AT).setValue(now);
    var viewCountCell = sheet.getRange(rowIndex, COL.VIEW_COUNT);
    viewCountCell.setValue((Number(viewCountCell.getValue()) || 0) + 1);

    return jsonResponse({ ok: true, cipherText: cipherText });
  } finally {
    lock.releaseLock();
  }
}

function updateAnalyticsViewerHash(id, viewerHash) {
  var sheet = getSpreadsheet().getSheetByName(ANALYTICS_SHEET);
  var rowIndex = findRowById(sheet, id);
  if (rowIndex) sheet.getRange(rowIndex, ACOL.VIEWER_HASH).setValue(viewerHash);
}

/* id (A列) からデータ行番号を探す。見つからなければ null */
function findRowById(sheet, id) {
  var lastRow = sheet.getLastRow();
  if (lastRow < DATA_START_ROW) return null;
  var ids = sheet.getRange(DATA_START_ROW, 1, lastRow - DATA_START_ROW + 1, 1).getValues();
  for (var i = 0; i < ids.length; i++) {
    if (ids[i][0] === id) return DATA_START_ROW + i;
  }
  return null;
}
