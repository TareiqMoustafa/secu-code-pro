# 🛡️ SecuCode Pro | Advanced Threat Intelligence Radar
**Developed by: Tarek Mostafa (2026)**

![Security](https://img.shields.io/badge/Security-Advanced-blue?style=for-the-badge&logo=target)
![Python](https://img.shields.io/badge/Backend-Flask-green?style=for-the-badge&logo=python)
![Supabase](https://img.shields.io/badge/Database-Supabase-emerald?style=for-the-badge&logo=supabase)
![License](https://img.shields.io/badge/License-CC_BY--NC--ND_4.0-red?style=for-the-badge)

## 🌐 نظرة عامة | Overview
نظام **سيكيور كود برو** هو محرك استخبارات تقني متطور مخصص لتحليل الروابط (URL Analysis) والكشف عن محاولات التصيد الاحتيالي (Phishing) والبرمجيات الخبيثة. يعمل النظام كدرع حماية استباقي يعتمد على خوارزميات المسافة اللفظية (Levenshtein) والربط مع قواعد بيانات عالمية.

---

## 🚀 المميزات التقنية | Key Features
* **التحليل السلوكي الذكي:** كشف روابط التصيد التي تحاول انتحال صفة المواقع العالمية (Google, PayPal, etc).
* **الربط مع VirusTotal:** فحص الروابط عبر أكثر من 70 محرك حماية عالمي بشكل لحظي.
* **نظام إحصائيات متزامن:** استخدام **Supabase RPC** لتحديث عداد الفحوصات والتهديدات المكتشفة فوراً.
* **حماية التردد (Rate Limiting):** دمج `Flask-Limiter` لمنع الهجمات العشوائية وإساءة استخدام الـ API.
* **تنبيهات تليجرام الفورية:** إرسال تقرير فني مفصل للمطور عند رصد أي رابط عالي الخطورة.

---

## 🛠️ البناء التقني | Tech Stack
* **Backend:** Python (Flask Framework)
* **Database:** Supabase (PostgreSQL with Edge Functions)
* **Frontend:** HTML5, Tailwind CSS, Lucide Icons
* **Security APIs:** VirusTotal v3 API, IPAPI (Server Intelligence)
* **Protection:** Flask-Limiter & Python-dotenv

---

## 📊 درجات الخطورة | Risk Assessment
| المستوى | الحالة | الإجراء المتبع |
| :--- | :--- | :--- |
| **Safe ✅** | موقع موثوق | يتم السماح بالدخول مع إظهار بيانات الخادم. |
| **Suspicious ⚠️** | نشاط مشبوه | تنبيه المستخدم بوجود كلمات تصيد أو انتحال بسيط. |
| **Critical 🚨** | تهديد مؤكد | حجب الرابط وإرسال تقرير فني فوري لتليجرام. |

---

## 📜 التراخيص والخصوصية | License & Privacy
هذا المشروع محمي بموجب رخصة:
**Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)**

* **يسمح بـ:** الاطلاع على الكود، استخدامه للأغراض التعليمية الشخصية، ومشاركته مع ذكر المصدر (طارق مصطفى).
* **يُمنع بـ:** الاستخدام التجاري، بيع الكود، أو إعادة توزيعه بعد تعديله دون إذن كتابي صريح.

> **Privacy Note:** يتبع النظام بروتوكول "تشفير البيانات اللحظي"؛ حيث لا يتم تخزين الروابط المفحوصة في سجلات دائمة لضمان خصوصية المستخدم.

---
## 📞 التواصل | Contact
**Main Developer:** Tarek Mostafa  
**Email:** [Taremoustafa12@gmail.com](mailto:Taremoustafa12@gmail.com)  
**Version:** 1.3.0 (2026 Update)  
**Status:** Operational 🟢

---
Copyright © 2026 - Tarek Mostafa. All rights reserved.
