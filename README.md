# Main.aspx Penetration Testing Suite

This comprehensive penetration testing framework is designed to identify and demonstrate security vulnerabilities in the ASP.NET Main.aspx page.

## ⚠️ IMPORTANT DISCLAIMER

**This tool is for educational and authorized security testing purposes only. Do not use against systems you do not own or have explicit permission to test.**

## Overview

The Main.aspx page contains several critical security vulnerabilities:

- **SQL Injection** (CRITICAL)
- **Authentication Bypass** (CRITICAL) 
- **Authorization Bypass** (HIGH)
- **Session Management Issues** (HIGH)
- **Cross-Site Scripting** (MEDIUM)
- **Information Disclosure** (MEDIUM)

## Installation

```bash
npm install
```

## Usage

### Static Code Analysis
```bash
npm test
```

### Dynamic Testing (requires running ASP.NET server)
```bash
# Ensure your ASP.NET application is running on localhost:44393
# Then uncomment the dynamic testing lines in pentest-runner.js
npm test
```

## Files Description

- `pentest-runner.js` - Main penetration testing framework
- `exploit-examples.js` - Educational exploit demonstrations
- `security-recommendations.md` - Detailed security assessment report

## Key Vulnerabilities Found

### 1. SQL Injection (CRITICAL)
```vb
' VULNERABLE CODE:
cmd = New SqlCommand("select top 1 id from dbo.alert_notification " & condition & "  order by id  desc", conn)

' SECURE FIX:
cmd = New SqlCommand("SELECT TOP 1 id FROM dbo.alert_notification WHERE userid = @userid ORDER BY id DESC", conn)
cmd.Parameters.AddWithValue("@userid", userid)
```

### 2. Authentication Bypass (CRITICAL)
```vb
' VULNERABLE CODE:
If Request.Cookies("userinfo") Is Nothing Then
    Response.Redirect("Login.aspx")
End If

' SECURE FIX:
If Session("authenticated") IsNot Nothing AndAlso Session("authenticated") = True Then
    ' User is authenticated
Else
    Response.Redirect("Login.aspx")
End If
```

## Test Categories

### Authentication Tests
- Cookie manipulation
- Session fixation
- Privilege escalation
- User impersonation

### Injection Tests
- SQL injection in userid parameter
- SQL injection in condition parameter
- Command injection attempts
- NoSQL injection (if applicable)

### Authorization Tests
- Horizontal privilege escalation
- Vertical privilege escalation
- Role-based access control bypass
- Special user privilege abuse

### Session Management Tests
- Session hijacking
- Session fixation
- Concurrent session handling
- Session timeout validation

## Security Recommendations

### Immediate Actions (Critical)
1. **Replace SQL string concatenation with parameterized queries**
2. **Implement server-side session management**
3. **Add comprehensive input validation**

### Short-term Actions (High Priority)
1. **Implement proper authorization checks**
2. **Add CSRF protection**
3. **Enable HTTPS and secure cookies**
4. **Add security headers**

### Long-term Actions (Medium Priority)
1. **Implement comprehensive logging**
2. **Add rate limiting**
3. **Set up monitoring and alerting**
4. **Regular security assessments**

## Example Attack Scenarios

### Scenario 1: Admin Account Takeover
```javascript
// Attacker crafts malicious cookie
const maliciousCookie = 'userinfo=username=ADMIN&usertype=1&userid=1&role=Admin&LA=Y';

// Accesses admin functions without authentication
fetch('/Main.aspx?n=ADMIN', {
    headers: { 'Cookie': maliciousCookie }
});
```

### Scenario 2: Database Compromise
```sql
-- SQL injection payload in userid parameter
1'; DROP TABLE userTBL; --

-- Data extraction payload
1' UNION SELECT username, password FROM userTBL --
```

## Compliance Impact

These vulnerabilities may violate:
- **OWASP Top 10** security standards
- **PCI DSS** requirements
- **GDPR** data protection requirements
- Industry-specific security standards

## Reporting

The tool generates comprehensive reports including:
- Vulnerability severity ratings
- Detailed technical descriptions
- Business impact assessments
- Specific remediation guidance
- Code examples for fixes

## Contributing

When contributing to this security testing framework:
1. Follow responsible disclosure practices
2. Ensure all examples are for educational purposes
3. Include proper security warnings
4. Test against isolated environments only

## Legal Notice

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

## Support

For questions about security testing or vulnerability remediation:
1. Review the detailed security recommendations
2. Consult OWASP security guidelines
3. Consider professional security assessment services

---

**Remember: Security is everyone's responsibility. Test responsibly and help make the web safer for everyone.**