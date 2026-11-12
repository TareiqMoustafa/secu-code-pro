# subscriptions.py
# إعدادات النظام المجاني الموحّد

# الحد اليومي للفحوصات لكل مستخدم
DAILY_LIMIT = 10

def get_daily_limit(plan=None):
    """
    إرجاع الحد اليومي الثابت لجميع المستخدمين.
    المعامل plan محتفظ به للتوافق مع الاستدعاءات القديمة.
    """
    return DAILY_LIMIT

def has_feature(plan, feature):
    """
    التحقق مما إذا كانت ميزة معينة متاحة.
    في النظام المجاني، جميع الميزات متاحة دائمًا.
    """
    # قائمة بجميع الميزات الممكنة في النظام
    all_features = [
        'basic_scan',
        'pdf_report',
        'ai_analysis',
        'bulk_scan',
        'link_preview',
        'screenshot',
        'priority_support'
    ]
    # أي ميزة ضمن القائمة متاحة
    return feature in all_features

# للتوافق مع الكود الذي قد يحاول الوصول إلى PLANS
PLANS = {
    "free": {
        "limit_per_day": DAILY_LIMIT,
        "price": 0,
        "stripe_price_id": None,
        "features": [
            "basic_scan",
            "pdf_report",
            "ai_analysis",
            "bulk_scan",
            "link_preview",
            "screenshot"
        ]
    }
}
