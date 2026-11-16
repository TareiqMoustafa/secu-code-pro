const $ = (id) => document.getElementById(id);

async function getApiBase() {
  const data = await chrome.storage.sync.get({ apiBase: "" });
  return (data.apiBase || "").replace(/\/$/, "");
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";
  $("pageUrl").textContent = url || "لا يمكن قراءة الرابط";
  $("scanBtn").disabled = !url || url.startsWith("chrome://") || url.startsWith("edge://");

  $("scanBtn").onclick = async () => {
    const base = await getApiBase();
    if (!base) {
      $("err").style.display = "block";
      $("err").textContent = "حدّد عنوان الموقع أولاً من صفحة الإعدادات (Options)";
      return;
    }
    $("err").style.display = "none";
    $("scanBtn").disabled = true;
    $("scanBtn").textContent = "جاري التحليل...";
    $("result").classList.remove("show");

    try {
      const res = await fetch(base + "/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ link: url }),
      });
      const data = await res.json();
      if (!data.success && data.error) throw new Error(data.error);

      const score = typeof data.points === "number" ? data.points : (data.risk_score || 0);
      const level = data.risk_level || "";
      let cls = "safe";
      if (level === "critical" || score >= 75) cls = "danger";
      else if (level === "suspicious" || score >= 45) cls = "warn";

      $("scoreNum").textContent = score;
      $("scoreNum").className = "n " + cls;
      $("scoreLabel").textContent = data.risk_label || level || "—";
      $("scoreLabel").className = "l " + cls;

      let meta = (data.summary || "") + "<br/>";
      if (data.report_id) {
        meta += '<a href="' + base + "/r/" + data.report_id + '" target="_blank">فتح التقرير · ' + data.report_id + "</a>";
      }
      $("meta").innerHTML = meta;
      $("result").classList.add("show");
    } catch (e) {
      $("err").style.display = "block";
      $("err").textContent = "فشل الفحص: " + (e.message || "تأكد من عنوان API");
    } finally {
      $("scanBtn").disabled = false;
      $("scanBtn").textContent = "فحص هذه الصفحة الآن";
    }
  };
}

init();
