Performing XSS vulnerability analysis...
=== Browser Storage Statistics ===
Total domains analyzed: 14

--- Cookie Statistics ---
Total cookies found: 53
Secure cookies: 42 (79.2% of total)
HttpOnly cookies: 25 (47.2% of total)
Third-party cookies: 0 (0.0% of total)

--- XSS Vulnerability Analysis ---
Total cookies analyzed for XSS: 53
Potentially vulnerable cookies: 0 (0.0% of total)


--- Cookie Age Statistics ---
Session cookies: 17 (32.1% of total)
Persistent cookies: 36 (67.9% of total)
Average age of persistent cookies: 310.0 days
Maximum age of persistent cookies: 399.0 days

Cookie age categories:
  Session: 17 (32.1% of total)
  Short_term: 7 (13.2% of total)
  Medium_term: 2 (3.8% of total)
  Long_term: 26 (49.1% of total)
  Expired: 1 (1.9% of total)

Cookie Age Distribution (days):
           0 | ████████ 8
           6 | █ 1
          27 | █ 1
          89 | █ 1
         179 | ████ 4
         182 | █ 1
         359 | █ 1
         364 | ████████ 8
         399 | ███████████ 11

Top 10 most common cookie names:
  __cf_bm: 4
  edgebucket: 2
  HWWAFSESTIME: 2
  HWWAFSESID: 2
  cf_clearance: 2
  GPS: 1
  YSC: 1
  VISITOR_INFO1_LIVE: 1
  VISITOR_PRIVACY_METADATA: 1
  __Secure-ROLLOUT_TOKEN: 1

--- Web Storage Statistics ---
Total localStorage items: 25
Total sessionStorage items: 5

Top 10 most common storage keys:
  localStorage:_grecaptcha: 1
  sessionStorage:serverTimestamps: 1
  localStorage:__appKit_@deepseek/blog_debugPanelEnabled: 1
  localStorage:__appKit_@deepseek/blog_lastSessionValue: 1
  localStorage:__tea_cache_first_20006840: 1
  localStorage:__tea_cache_tokens_20006840: 1
  sessionStorage:__tea_session_id_20006840: 1
  localStorage:chat-preferences: 1
  localStorage:i18nextLng: 1
  localStorage:model-select-tutorial: 1

--- Per-Domain Statistics ---
+--------------------------+-----------+-----------------+---------------+
| Domain                   |   Cookies |   Storage Items |   Total Items |
+==========================+===========+=================+===============+
| https://grok.com         |         5 |               6 |            11 |
+--------------------------+-----------+-----------------+---------------+
| https://www.reddit.com   |         7 |               2 |             9 |
+--------------------------+-----------+-----------------+---------------+
| https://www.facebook.com |         4 |               5 |             9 |
+--------------------------+-----------+-----------------+---------------+
| https://www.x.com        |         7 |               0 |             7 |
+--------------------------+-----------+-----------------+---------------+
| https://www.amazon.com   |         5 |               0 |             5 |
+--------------------------+-----------+-----------------+---------------+
| https://www.youtube.com  |         5 |               0 |             5 |
+--------------------------+-----------+-----------------+---------------+
| https://www.google.com   |         2 |               0 |             2 |
+--------------------------+-----------+-----------------+---------------+
| https://www.deepseek.com |         2 |               0 |             2 |
+--------------------------+-----------+-----------------+---------------+
| https://chatgpt.com      |         1 |               0 |             1 |
+--------------------------+-----------+-----------------+---------------+
