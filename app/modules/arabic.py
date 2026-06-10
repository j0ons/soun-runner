"""Arabic executive summary for client-facing reports.

UAE differentiator: the decision-maker who signs the cheque often prefers
Arabic, while the IT contact reads the English body. This module builds a
one-page Arabic executive summary from ReportData — entirely data-driven
(no translation service): findings map to pre-written Modern Standard
Arabic phrases through keyword buckets, the same matching approach
compliance.py uses.

Grammar note: Arabic number agreement is non-trivial (1 جهاز, 2 جهازان,
3-10 أجهزة, 11+ جهازًا). Dynamic counts either go through `_count_ar()`
or appear as "label: number" pairs, so the generated text stays
grammatically correct for any count.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Arabic month names for the Gregorian calendar (UAE business convention).
_MONTHS_AR = {
    "January": "يناير", "February": "فبراير", "March": "مارس",
    "April": "أبريل", "May": "مايو", "June": "يونيو",
    "July": "يوليو", "August": "أغسطس", "September": "سبتمبر",
    "October": "أكتوبر", "November": "نوفمبر", "December": "ديسمبر",
}

_RISK_AR = {
    "critical": "حرج", "high": "مرتفع", "medium": "متوسط",
    "low": "منخفض", "info": "ضئيل",
}

# Severity chips shown under the intro (label: count keeps grammar safe).
_SEVERITY_CHIPS = [
    ("critical", "نتائج حرجة", "#ef4444"),
    ("high", "عالية الخطورة", "#f97316"),
    ("medium", "متوسطة الخطورة", "#eab308"),
    ("low", "منخفضة الخطورة", "#22c55e"),
]

# Finding buckets: (key, keywords matched against title+service+detail,
# highlight bullet, urgent recommendation). Order = priority in the page.
_BUCKETS = [
    ("rdp", ("rdp", "remote desktop", "3389"),
     "خدمة سطح المكتب البعيد (RDP) مكشوفة على الشبكة — وهي المدخل الأول لهجمات برامج الفدية في المنطقة",
     "نقل خدمة سطح المكتب البعيد (RDP) خلف شبكة VPN أو تقييد الوصول إليها فورًا"),
    ("creds", ("default credential", "default password", "factory"),
     "أجهزة تعمل بكلمات المرور الافتراضية من المصنع — يمكن لأي مهاجم الدخول إليها مباشرة",
     "تغيير جميع كلمات المرور الافتراضية إلى كلمات مرور قوية وفريدة"),
    ("backup", ("backup", "ransomware recovery"),
     "غياب نسخ احتياطية موثوقة ومعزولة — ما يضاعف أثر أي هجوم فدية على استمرارية الأعمال",
     "تفعيل نسخ احتياطي يومي معزول عن الشبكة واختبار الاستعادة دوريًا"),
    ("smb", ("smb", "445", "file sharing"),
     "خدمة مشاركة الملفات (SMB) مكشوفة — تتيح للمهاجم الانتشار الجانبي بين الأجهزة",
     "تقييد منفذ مشاركة الملفات (445) على الخوادم المخصصة وتعطيل SMBv1"),
    ("database", ("database", "mysql", "mssql", "sql server", "postgres", "redis", "mongo", "elastic", "1433", "3306", "5432"),
     "قواعد بيانات يمكن الوصول إليها عبر الشبكة دون عزل كافٍ — خطر مباشر على بيانات العملاء",
     "عزل قواعد البيانات خلف جدار حماية وقصر الوصول على خوادم التطبيقات فقط"),
    ("telnet", ("telnet",),
     "خدمة Telnet تنقل كلمات المرور نصًا مكشوفًا دون أي تشفير",
     "تعطيل خدمة Telnet نهائيًا والاستعاضة عنها بـ SSH"),
    ("vnc", ("vnc", "5900"),
     "خدمة تحكم عن بُعد (VNC) قد تعمل دون كلمة مرور قوية — تتيح السيطرة الكاملة على الجهاز",
     "تأمين خدمة VNC بكلمة مرور قوية أو تعطيلها إن لم تكن ضرورية"),
    ("email", ("dmarc", "spf", "dkim", "email security"),
     "إعدادات حماية البريد الإلكتروني غير مكتملة — تتيح إرسال رسائل منتحلة باسم شركتكم",
     "ضبط سجلات SPF وDKIM وDMARC لمنع انتحال هوية البريد الرسمي"),
    ("ssl", ("ssl", "tls", "certificate", "cipher"),
     "شهادات أو بروتوكولات تشفير ضعيفة أو منتهية الصلاحية على خدمات الويب",
     "تجديد الشهادات الرقمية وتعطيل بروتوكولات التشفير القديمة"),
    ("panel", ("admin panel", "management interface", "router", "idrac", "ilo", "web interface"),
     "لوحات تحكم إدارية مكشوفة على الشبكة الداخلية دون تقييد",
     "حصر الوصول إلى لوحات التحكم الإدارية في أجهزة الإدارة المصرح بها"),
    ("camera", ("camera", "cctv", "rtsp", "hikvision", "dahua"),
     "كاميرات مراقبة متصلة بالشبكة الرئيسية دون عزل — كثيرًا ما تكون أضعف حلقة في الشبكة",
     "عزل كاميرات المراقبة في شبكة فرعية (VLAN) مستقلة"),
    ("segmentation", ("vlan", "segmentation", "lateral"),
     "غياب تقسيم الشبكة (VLAN) يسمح للمهاجم بالانتقال بحرية بين الأنظمة",
     "تقسيم الشبكة إلى مناطق معزولة (ضيوف، كاميرات، خوادم، موظفون)"),
    ("firewall", ("firewall",),
     "إعدادات جدار الحماية تحتاج إلى مراجعة وتشديد",
     "مراجعة قواعد جدار الحماية واعتماد مبدأ الرفض الافتراضي"),
    ("upnp", ("upnp",),
     "خدمة UPnP مفعّلة وقد تفتح منافذ نحو الإنترنت تلقائيًا دون علمكم",
     "تعطيل خدمة UPnP على أجهزة التوجيه"),
    ("snmp", ("snmp",),
     "خدمة SNMP بإعدادات افتراضية تكشف معلومات حساسة عن الشبكة",
     "تغيير نصوص SNMP الافتراضية أو تعطيل الخدمة"),
]


@dataclass
class ArabicSummary:
    title: str = "الملخص التنفيذي"
    intro: str = ""
    risk_line: str = ""
    risk_score: int = 0
    risk_label_ar: str = ""
    risk_color: str = "#6b7280"
    chips: list = field(default_factory=list)        # [(label, count, color)]
    highlights: list = field(default_factory=list)   # Arabic bullets
    recommendations: list = field(default_factory=list)
    closing: str = ""


def _count_ar(n: int, one: str, two: str, few: str, many: str) -> str:
    """Arabic count agreement: 1 / 2 / 3-10 / 11+ forms."""
    if n == 1:
        return one
    if n == 2:
        return two
    if 3 <= n <= 10:
        return f"{n} {few}"
    return f"{n} {many}"


def _date_ar(generated_at: str) -> str:
    """'10 June 2026, 08:57 UTC' -> '10 يونيو 2026'; falls back to input."""
    m = re.match(r"(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})", generated_at or "")
    if m and m.group(2) in _MONTHS_AR:
        return f"{int(m.group(1))} {_MONTHS_AR[m.group(2)]} {m.group(3)}"
    return generated_at or ""


def build_arabic_summary(r) -> ArabicSummary | None:
    """Build the Arabic executive summary from a ReportData. None = skip section."""
    if r.scan_error:
        return None

    s = ArabicSummary()
    date_ar = _date_ar(r.generated_at)

    if r.hosts_up == 0:
        s.intro = (
            f"أجرت صون الحصن للأمن السيبراني فحصًا أمنيًا لشبكة {r.client_name} "
            f"بتاريخ {date_ar} على النطاق {r.target}، ولم يرصد الفحص أجهزة نشطة. "
            "قد يعود ذلك إلى نطاق غير صحيح أو إلى حجب أجهزة الشبكة لطلبات الاكتشاف."
        )
        s.closing = "يسرّ فريق صون الحصن إعادة الفحص بعد التحقق من إعدادات الشبكة."
        return s

    devices = _count_ar(r.hosts_up, "جهازًا واحدًا نشطًا", "جهازين نشطين",
                        "أجهزة نشطة", "جهازًا نشطًا")
    services = _count_ar(r.total_open_ports, "منفذًا مفتوحًا واحدًا", "منفذين مفتوحين",
                         "منافذ مفتوحة", "منفذًا مفتوحًا")
    s.intro = (
        f"أجرت صون الحصن للأمن السيبراني تقييمًا أمنيًا لشبكة {r.client_name} "
        f"بتاريخ {date_ar}. شمل التقييم نطاق الشبكة {r.target}، حيث رصد الفحص "
        f"{devices} وإجمالي {services} على مستوى الشبكة."
    )

    # Overall risk line — numbers appear as digits, labels are static Arabic.
    s.risk_score = r.risk_score
    s.risk_label_ar = _RISK_AR.get(r.overall_risk, "غير محدد")
    s.risk_color = r.overall_risk_color
    s.risk_line = (
        f"بلغت درجة المخاطر الإجمالية {r.risk_score} من 100 — "
        f"مستوى الخطورة العام: {s.risk_label_ar}."
    )

    counts = {
        "critical": r.critical_count, "high": r.high_count,
        "medium": r.medium_count, "low": r.low_count,
    }
    s.chips = [(label, counts[key], color)
               for key, label, color in _SEVERITY_CHIPS if counts[key] > 0]

    # Bucket the findings (critical/high/medium only) into Arabic highlights.
    weight = {"critical": 3, "high": 2, "medium": 1}
    hit: dict[str, dict] = {}
    for f in r.findings:
        w = weight.get(f.risk, 0)
        if w == 0:
            continue
        text = f"{f.title} {f.service} {f.detail}".lower()
        for key, keywords, highlight, rec in _BUCKETS:
            if any(k in text for k in keywords):
                b = hit.setdefault(key, {"w": 0, "n": 0, "hl": highlight, "rec": rec})
                b["w"] = max(b["w"], w)
                b["n"] += 1
                break

    ordered = sorted(hit.values(), key=lambda b: (-b["w"], -b["n"]))
    for b in ordered[:6]:
        suffix = ""
        if b["n"] > 1:
            suffix = " (" + _count_ar(b["n"], "نتيجة واحدة", "نتيجتان",
                                      "نتائج", "نتيجة") + ")"
        s.highlights.append(b["hl"] + suffix)
    s.recommendations = [b["rec"] for b in ordered[:5]]
    if not s.recommendations and r.total_findings:
        s.recommendations.append("معالجة النتائج وفق خطة الإصلاح التفصيلية المرفقة في هذا التقرير")

    if not s.highlights:
        s.highlights.append(
            "لم يرصد الفحص مخاطر جوهرية على مستوى الشبكة — وضع الشبكة جيد عمومًا، "
            "مع توصيات تحسين واردة في متن التقرير."
        )

    s.closing = (
        "يتضمن هذا التقرير خطوة إصلاح عملية لكل نتيجة، مرتبة حسب الأولوية. "
        "يسرّ فريق صون الحصن للأمن السيبراني تنفيذ أعمال المعالجة كاملةً، "
        "ثم إعادة الفحص للتحقق من إغلاق الثغرات — تواصلوا معنا للحصول على عرض عمل."
    )
    return s
