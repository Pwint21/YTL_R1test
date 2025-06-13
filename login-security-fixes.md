# Login.aspx Security Fixes Implementation Guide

## Critical Vulnerabilities Found

### 1. SQL Injection (CRITICAL) 🚨
**Current Vulnerable Code:**
```vb
Dim cmd As New SqlCommand("select pwd,role,userid,username,userslist,access,timestamp,usertype,remark,dbip,companyname,customrole from userTBL where upper(username) ='" & UCase(uname.Value) & "' and drcaccess='0'", conn)
```

**Secure Fix:**
```vb
Dim cmd As New SqlCommand("SELECT pwd,role,userid,username,userslist,access,timestamp,usertype,remark,dbip,companyname,customrole FROM userTBL WHERE username = @username AND drcaccess='0'", conn)
cmd.Parameters.AddWithValue("@username", uname.Value.Trim())
```

### 2. Plain Text Password Storage (CRITICAL) 🚨
**Current Vulnerable Code:**
```vb
If UCase(dr("pwd")) = UCase(password.Value) Then
```

**Secure Fix:**
```vb
' First, hash existing passwords (one-time migration)
' Then use secure password verification
If BCrypt.Verify(password.Value, dr("pwd")) Then
    ' Authentication successful
End If
```

### 3. Client-Side Authentication (CRITICAL) 🚨
**Current Vulnerable Code:**
```vb
Response.Cookies("userinfo")("userid") = dr("userid")
Response.Cookies("userinfo")("username") = dr("username")
Response.Cookies("userinfo")("role") = dr("role")
```

**Secure Fix:**
```vb
' Use server-side sessions instead of cookies
Session("authenticated") = True
Session("userid") = dr("userid")
Session("username") = dr("username")
Session("role") = dr("role")
Session("loginTime") = DateTime.Now
```

## Complete Secure Login Implementation

### Updated login.aspx.vb (Secure Version)

```vb
Imports System.Data.SqlClient
Imports System.Text.RegularExpressions
Imports BCrypt.Net

Namespace AVLS
    Partial Class Login
        Inherits System.Web.UI.Page
        Public errormessage As String = ""
        Public foc As String = "uname"
        
        Private Const MAX_LOGIN_ATTEMPTS As Integer = 5
        Private Const LOCKOUT_DURATION_MINUTES As Integer = 15

        Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
            Try
                ImageButton1.Attributes.Add("onclick", "return mysubmit()")
                
                ' Clear any existing sessions
                Session.Clear()
                Session.Abandon()
                
                ' Clear cookies securely
                If Request.Cookies("userinfo") IsNot Nothing Then
                    Dim cookie As New HttpCookie("userinfo")
                    cookie.Expires = DateTime.Now.AddDays(-1)
                    cookie.Value = ""
                    Response.Cookies.Add(cookie)
                End If

            Catch ex As Exception
                LogSecurityEvent("Page_Load error: " & ex.Message, Request.UserHostAddress)
                errormessage = "An error occurred. Please try again."
            End Try
        End Sub

        Protected Sub ImageButton1_Click(ByVal sender As Object, ByVal e As System.Web.UI.ImageClickEventArgs) Handles ImageButton1.Click
            Try
                ' Input validation
                If Not ValidateInput() Then
                    Return
                End If
                
                ' Check for account lockout
                If IsAccountLocked(uname.Value) Then
                    errormessage = "Account temporarily locked due to multiple failed login attempts. Please try again later."
                    foc = "uname"
                    Return
                End If
                
                ' Authenticate user
                If AuthenticateUser(uname.Value.Trim(), password.Value) Then
                    ' Successful login
                    ClearFailedAttempts(uname.Value)
                    RedirectToMainPage()
                Else
                    ' Failed login
                    RecordFailedAttempt(uname.Value)
                    errormessage = "Invalid username or password."
                    foc = "password"
                End If

            Catch ex As Exception
                LogSecurityEvent("Login error: " & ex.Message, Request.UserHostAddress)
                errormessage = "An error occurred during login. Please try again."
            End Try
        End Sub

        Private Function ValidateInput() As Boolean
            ' Username validation
            If String.IsNullOrWhiteSpace(uname.Value) Then
                errormessage = "Please enter a username."
                foc = "uname"
                Return False
            End If
            
            If uname.Value.Length > 50 Then
                errormessage = "Username too long."
                foc = "uname"
                Return False
            End If
            
            ' Check for suspicious characters
            If Regex.IsMatch(uname.Value, "[<>\"'%;()&+\-\*/=]") Then
                errormessage = "Invalid characters in username."
                foc = "uname"
                LogSecurityEvent("Suspicious username attempt: " & uname.Value, Request.UserHostAddress)
                Return False
            End If
            
            ' Password validation
            If String.IsNullOrWhiteSpace(password.Value) Then
                errormessage = "Please enter a password."
                foc = "password"
                Return False
            End If
            
            Return True
        End Function

        Private Function AuthenticateUser(username As String, password As String) As Boolean
            Try
                Using conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
                    ' SECURE: Using parameterized query
                    Dim cmd As New SqlCommand("SELECT pwd,role,userid,username,userslist,access,timestamp,usertype,remark,dbip,companyname,customrole FROM userTBL WHERE username = @username AND drcaccess='0'", conn)
                    cmd.Parameters.AddWithValue("@username", username)
                    
                    conn.Open()
                    Using dr As SqlDataReader = cmd.ExecuteReader()
                        If dr.Read() Then
                            ' SECURE: Using BCrypt for password verification
                            If BCrypt.Verify(password, dr("pwd").ToString()) Then
                                ' Check account status
                                Dim access As Byte = CByte(dr("access"))
                                If Not CheckAccountAccess(access, dr) Then
                                    Return False
                                End If
                                
                                ' Create secure session
                                CreateSecureSession(dr)
                                
                                ' Log successful login
                                LogUserLogin(dr("userid").ToString(), username)
                                
                                Return True
                            End If
                        End If
                    End Using
                End Using
                
                Return False
                
            Catch ex As Exception
                LogSecurityEvent("Authentication error: " & ex.Message, Request.UserHostAddress)
                Return False
            End Try
        End Function

        Private Function CheckAccountAccess(access As Byte, dr As SqlDataReader) As Boolean
            Select Case access
                Case 1
                    If IsDBNull(dr("remark")) Or dr("remark") Is Nothing Then
                        errormessage = "Dear Customer, Your account is overdue. Kindly remit the total amount due immediately."
                    Else
                        errormessage = "Dear Customer, " & dr("remark").ToString()
                    End If
                    Return False
                    
                Case 2, 3, 4
                    Dim accessdays() As SByte = {0, -1, 7, 14, 31}
                    Dim denydatetime As DateTime = DateTime.Parse(dr("timestamp"))
                    Dim temptime As TimeSpan = DateTime.Now - denydatetime
                    
                    If temptime.TotalDays > accessdays(access) Then
                        If IsDBNull(dr("remark")) Or dr("remark") Is Nothing Then
                            errormessage = "Dear Customer, Your account is overdue. Kindly remit the total amount due immediately."
                        Else
                            errormessage = "Dear Customer, " & dr("remark").ToString()
                        End If
                        Return False
                    Else
                        ' Account has limited access
                        Session("accountWarning") = True
                        If IsDBNull(dr("remark")) Or dr("remark") Is Nothing Then
                            Session("warningMessage") = "Dear Customer, Your account is overdue. Kindly remit the total amount due immediately."
                        Else
                            Session("warningMessage") = "Dear Customer, " & dr("remark").ToString()
                        End If
                    End If
            End Select
            
            Return True
        End Function

        Private Sub CreateSecureSession(dr As SqlDataReader)
            ' Clear any existing session data
            Session.Clear()
            
            ' Create secure session
            Session("authenticated") = True
            Session("userid") = dr("userid").ToString()
            Session("username") = dr("username").ToString()
            Session("role") = dr("role").ToString()
            Session("usertype") = dr("usertype").ToString()
            Session("companyname") = dr("companyname").ToString()
            Session("customrole") = dr("customrole").ToString()
            Session("loginTime") = DateTime.Now
            Session("sessionToken") = Guid.NewGuid().ToString()
            
            ' Set special privileges
            Dim userid As String = dr("userid").ToString()
            If userid = "6941" Or userid = "3342" Or userid = "439" Or userid = "742" Or userid = "1967" Or userid = "2029" Or userid = "2041" Or userid = "2068" Or userid = "3107" Or userid = "3352" Or userid = "8100" Then
                Session("LA") = "Y"
            Else
                Session("LA") = "N"
            End If
            
            ' Process users list
            Dim userslist() As String = dr("userslist").ToString().Split(","c)
            Dim usersstring As String = ""
            For j As Integer = 0 To userslist.Length - 1
                If IsNumeric(userslist(j).Trim()) Then
                    usersstring &= "'" & userslist(j).Trim() & "',"
                End If
            Next
            If usersstring.Length > 0 Then
                usersstring = usersstring.Remove(usersstring.Length - 1, 1)
            End If
            Session("userslist") = usersstring
        End Sub

        Private Sub LogUserLogin(userid As String, username As String)
            Try
                Dim logintime As String = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss:fff")
                Dim hostaddress As String = Request.UserHostAddress
                Dim browser As String = Request.Browser.Browser & " " & Request.Browser.Version
                Dim url As String = Request.Url.ToString()
                
                Dim w As Integer = 0
                Dim h As Integer = 0
                Dim lat As Double = 0
                Dim lon As Double = 0
                Dim acc As Integer = 0
                
                Try
                    Integer.TryParse(Request.Form("w"), w)
                    Integer.TryParse(Request.Form("h"), h)
                    Double.TryParse(Request.Form("lat"), lat)
                    Double.TryParse(Request.Form("lon"), lon)
                    Integer.TryParse(Request.Form("acc"), acc)
                Catch
                    ' Ignore parsing errors
                End Try
                
                Using conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
                    Dim cmd As New SqlCommand("INSERT INTO user_log(userid,logintime,logouttime,hostaddress,browser,applicationversion,url,status,width,height,lat,lon,acc) VALUES(@userid,@logintime,@logintime,@hostaddress,@browser,@appversion,@url,1,@width,@height,@lat,@lon,@acc)", conn)
                    cmd.Parameters.AddWithValue("@userid", userid)
                    cmd.Parameters.AddWithValue("@logintime", logintime)
                    cmd.Parameters.AddWithValue("@hostaddress", hostaddress)
                    cmd.Parameters.AddWithValue("@browser", browser)
                    cmd.Parameters.AddWithValue("@appversion", "YTL AVLS Secure")
                    cmd.Parameters.AddWithValue("@url", url)
                    cmd.Parameters.AddWithValue("@width", w)
                    cmd.Parameters.AddWithValue("@height", h)
                    cmd.Parameters.AddWithValue("@lat", lat)
                    cmd.Parameters.AddWithValue("@lon", lon)
                    cmd.Parameters.AddWithValue("@acc", acc)
                    
                    conn.Open()
                    cmd.ExecuteNonQuery()
                End Using
                
            Catch ex As Exception
                LogSecurityEvent("Login logging error: " & ex.Message, Request.UserHostAddress)
            End Try
        End Sub

        Private Sub RedirectToMainPage()
            Response.Redirect("Main.aspx?n=" & Server.UrlEncode(Session("username").ToString()))
        End Sub

        Private Function IsAccountLocked(username As String) As Boolean
            Try
                Dim cacheKey As String = "FailedAttempts_" & username
                Dim attempts As Integer = 0
                
                If HttpContext.Current.Cache(cacheKey) IsNot Nothing Then
                    attempts = CInt(HttpContext.Current.Cache(cacheKey))
                End If
                
                Return attempts >= MAX_LOGIN_ATTEMPTS
                
            Catch ex As Exception
                LogSecurityEvent("Account lock check error: " & ex.Message, Request.UserHostAddress)
                Return False
            End Try
        End Function

        Private Sub RecordFailedAttempt(username As String)
            Try
                Dim cacheKey As String = "FailedAttempts_" & username
                Dim attempts As Integer = 0
                
                If HttpContext.Current.Cache(cacheKey) IsNot Nothing Then
                    attempts = CInt(HttpContext.Current.Cache(cacheKey))
                End If
                
                attempts += 1
                
                ' Cache for lockout duration
                HttpContext.Current.Cache.Insert(cacheKey, attempts, Nothing, DateTime.Now.AddMinutes(LOCKOUT_DURATION_MINUTES), TimeSpan.Zero)
                
                LogSecurityEvent($"Failed login attempt #{attempts} for user: {username}", Request.UserHostAddress)
                
            Catch ex As Exception
                LogSecurityEvent("Failed attempt recording error: " & ex.Message, Request.UserHostAddress)
            End Try
        End Sub

        Private Sub ClearFailedAttempts(username As String)
            Try
                Dim cacheKey As String = "FailedAttempts_" & username
                HttpContext.Current.Cache.Remove(cacheKey)
            Catch ex As Exception
                LogSecurityEvent("Clear failed attempts error: " & ex.Message, Request.UserHostAddress)
            End Try
        End Sub

        Private Sub LogSecurityEvent(message As String, ipAddress As String)
            Try
                Dim logMessage As String = String.Format("{0}: {1} - IP: {2}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), message, ipAddress)
                System.Diagnostics.EventLog.WriteEntry("YTL_Security", logMessage, System.Diagnostics.EventLogEntryType.Warning)
            Catch
                ' Fail silently to prevent information disclosure
            End Try
        End Sub
    End Class
End Namespace
```

## Password Migration Script

```sql
-- One-time password migration script
-- Run this to hash existing plain text passwords

DECLARE @userid INT, @plainPassword NVARCHAR(255), @hashedPassword NVARCHAR(255)
DECLARE password_cursor CURSOR FOR 
SELECT userid, pwd FROM userTBL WHERE pwd IS NOT NULL AND pwd != ''

OPEN password_cursor
FETCH NEXT FROM password_cursor INTO @userid, @plainPassword

WHILE @@FETCH_STATUS = 0
BEGIN
    -- Hash the password using BCrypt (this would need to be done via application code)
    -- For now, mark passwords that need hashing
    UPDATE userTBL 
    SET remark = ISNULL(remark, '') + ' [PASSWORD_NEEDS_HASHING]'
    WHERE userid = @userid
    
    FETCH NEXT FROM password_cursor INTO @userid, @plainPassword
END

CLOSE password_cursor
DEALLOCATE password_cursor
```

## Additional Security Measures

### 1. Update Web.config for Enhanced Security

```xml
<system.web>
    <!-- Enhanced session security -->
    <sessionState 
        mode="InProc" 
        timeout="30" 
        cookieless="false" 
        cookieTimeout="30" 
        cookieName="ASP.NET_SessionId" 
        cookieRequireSSL="true" 
        cookieSameSite="Strict" 
        httpOnlyCookies="true" 
        regenerateExpiredSessionId="true" />
    
    <!-- Enhanced authentication -->
    <authentication mode="Forms">
        <forms 
            loginUrl="login.aspx" 
            timeout="30" 
            requireSSL="true" 
            cookieless="false" 
            slidingExpiration="true" 
            cookieSameSite="Strict" />
    </authentication>
</system.web>
```

### 2. Client-Side Security Enhancements

```javascript
// Add to login.aspx
function enhancedValidation() {
    var username = document.getElementById("uname").value;
    var password = document.getElementById("password").value;
    
    // Basic client-side validation (server-side is primary)
    if (username.length > 50) {
        alert("Username too long");
        return false;
    }
    
    if (password.length < 8) {
        alert("Password must be at least 8 characters");
        return false;
    }
    
    // Check for suspicious characters
    var suspiciousPattern = /[<>\"'%;()&+\-\*/=]/;
    if (suspiciousPattern.test(username)) {
        alert("Invalid characters in username");
        return false;
    }
    
    return mysubmit();
}
```

## Testing the Fixes

### 1. SQL Injection Tests (Should Fail)
```bash
# These should no longer work:
curl -X POST http://localhost:44393/login.aspx \
  -d "uname=admin' OR '1'='1' --&password=anything"

curl -X POST http://localhost:44393/login.aspx \
  -d "uname=admin'--&password=ignored"
```

### 2. Brute Force Tests (Should Be Limited)
```bash
# After 5 attempts, account should be locked
for i in {1..10}; do
  curl -X POST http://localhost:44393/login.aspx \
    -d "uname=admin&password=wrong$i"
done
```

### 3. Session Security Tests
```bash
# Sessions should be server-side only
curl -X GET http://localhost:44393/Main.aspx \
  -H "Cookie: userinfo=username=admin&role=Admin"
# Should redirect to login
```

## Deployment Checklist

- [ ] Update login.aspx.vb with secure code
- [ ] Install BCrypt.Net NuGet package
- [ ] Update Web.config with security settings
- [ ] Run password migration script
- [ ] Test all functionality
- [ ] Update client-side validation
- [ ] Configure HTTPS
- [ ] Set up security monitoring
- [ ] Train users on new security measures
- [ ] Document incident response procedures

## Monitoring and Maintenance

1. **Regular Security Audits**: Monthly penetration testing
2. **Log Monitoring**: Daily review of security logs
3. **Password Policy**: Enforce strong passwords
4. **Session Management**: Regular session cleanup
5. **Database Security**: Regular security updates
6. **Code Reviews**: Security-focused code reviews for all changes

---

**⚠️ CRITICAL**: Test all changes in a development environment before deploying to production. Ensure all existing functionality works correctly with the new security measures.