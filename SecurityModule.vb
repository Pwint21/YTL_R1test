Imports System.Web
Imports System.Text.RegularExpressions

Public Class SecurityModule
    Implements IHttpModule

    Public Sub Init(context As HttpApplication) Implements IHttpModule.Init
        AddHandler context.BeginRequest, AddressOf OnBeginRequest
        AddHandler context.PreExecuteRequestHandler, AddressOf OnPreExecuteRequestHandler
        AddHandler context.EndRequest, AddressOf OnEndRequest
    End Sub

    Private Sub OnBeginRequest(sender As Object, e As EventArgs)
        Dim context As HttpContext = HttpContext.Current
        
        ' SECURITY FIX: Add security headers
        AddSecurityHeaders(context.Response)
        
        ' SECURITY FIX: Block suspicious requests
        If IsSuspiciousRequest(context.Request) Then
            LogSecurityEvent("Suspicious request blocked from IP: " & context.Request.UserHostAddress)
            context.Response.StatusCode = 400
            context.Response.StatusDescription = "Bad Request"
            context.Response.End()
            Return
        End If
        
        ' SECURITY FIX: Rate limiting
        If IsRateLimited(context.Request) Then
            LogSecurityEvent("Rate limit exceeded for IP: " & context.Request.UserHostAddress)
            context.Response.StatusCode = 429
            context.Response.StatusDescription = "Too Many Requests"
            context.Response.Headers.Add("Retry-After", "60")
            context.Response.End()
            Return
        End If
    End Sub

    Private Sub OnPreExecuteRequestHandler(sender As Object, e As EventArgs)
        Dim context As HttpContext = HttpContext.Current
        
        ' SECURITY FIX: Validate session for protected pages
        If IsProtectedPage(context.Request.Url.AbsolutePath) Then
            If Not IsValidSession(context) Then
                LogSecurityEvent("Unauthorized access attempt to protected page: " & context.Request.Url.AbsolutePath & " from IP: " & context.Request.UserHostAddress)
                context.Response.Redirect("login.aspx", True)
                Return
            End If
        End If
    End Sub

    Private Sub OnEndRequest(sender As Object, e As EventArgs)
        Dim context As HttpContext = HttpContext.Current
        
        ' SECURITY FIX: Remove server information
        context.Response.Headers.Remove("Server")
        context.Response.Headers.Remove("X-AspNet-Version")
        context.Response.Headers.Remove("X-AspNetMvc-Version")
        context.Response.Headers.Remove("X-Powered-By")
    End Sub

    Private Sub AddSecurityHeaders(response As HttpResponse)
        Try
            ' Add security headers if not already present
            If String.IsNullOrEmpty(response.Headers("X-Frame-Options")) Then
                response.Headers.Add("X-Frame-Options", "DENY")
            End If
            
            If String.IsNullOrEmpty(response.Headers("X-Content-Type-Options")) Then
                response.Headers.Add("X-Content-Type-Options", "nosniff")
            End If
            
            If String.IsNullOrEmpty(response.Headers("X-XSS-Protection")) Then
                response.Headers.Add("X-XSS-Protection", "1; mode=block")
            End If
            
            If String.IsNullOrEmpty(response.Headers("Strict-Transport-Security")) Then
                response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            End If
            
            If String.IsNullOrEmpty(response.Headers("Referrer-Policy")) Then
                response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin")
            End If
        Catch ex As Exception
            LogSecurityEvent("Error adding security headers: " & ex.Message)
        End Try
    End Sub

    Private Function IsSuspiciousRequest(request As HttpRequest) As Boolean
        Try
            ' Check for SQL injection patterns
            Dim sqlPatterns() As String = {
                "(\%27)|(\')|(\-\-)|(\%23)|(#)",
                "((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                "\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                "((\%27)|(\'))union",
                "exec(\s|\+)+(s|x)p\w+",
                "drop\s+table",
                "insert\s+into",
                "delete\s+from",
                "update\s+\w+\s+set"
            }
            
            ' Check for XSS patterns
            Dim xssPatterns() As String = {
                "<script[^>]*>.*?</script>",
                "javascript:",
                "vbscript:",
                "onload\s*=",
                "onerror\s*=",
                "onclick\s*=",
                "onmouseover\s*=",
                "<iframe[^>]*>",
                "<object[^>]*>",
                "<embed[^>]*>"
            }
            
            ' Check for path traversal
            Dim pathTraversalPatterns() As String = {
                "\.\./",
                "\.\.\\",
                "%2e%2e%2f",
                "%2e%2e\\",
                "..%2f",
                "..%5c"
            }
            
            Dim queryString As String = request.QueryString.ToString().ToLower()
            Dim formData As String = ""
            Dim urlPath As String = request.Url.AbsolutePath.ToLower()
            
            ' Check form data if POST request
            If request.HttpMethod = "POST" AndAlso request.Form IsNot Nothing Then
                For Each key As String In request.Form.AllKeys
                    If request.Form(key) IsNot Nothing Then
                        formData &= request.Form(key) & " "
                    End If
                Next
                formData = formData.ToLower()
            End If
            
            ' Check all patterns
            Dim allPatterns() As String() = {sqlPatterns, xssPatterns, pathTraversalPatterns}
            Dim testStrings() As String = {queryString, formData, urlPath}
            
            For Each patternGroup As String() In allPatterns
                For Each pattern As String In patternGroup
                    For Each testString As String In testStrings
                        If Not String.IsNullOrEmpty(testString) AndAlso Regex.IsMatch(testString, pattern, RegexOptions.IgnoreCase) Then
                            LogSecurityEvent("Suspicious pattern detected: " & pattern & " in: " & testString.Substring(0, Math.Min(100, testString.Length)))
                            Return True
                        End If
                    Next
                Next
            Next
            
            ' Check for suspicious user agents
            Dim userAgent As String = request.UserAgent
            If Not String.IsNullOrEmpty(userAgent) Then
                Dim suspiciousAgents() As String = {"sqlmap", "nikto", "nessus", "burp", "zap", "w3af", "acunetix"}
                For Each agent As String In suspiciousAgents
                    If userAgent.ToLower().Contains(agent) Then
                        LogSecurityEvent("Suspicious user agent detected: " & userAgent)
                        Return True
                    End If
                Next
            End If
            
            Return False
        Catch ex As Exception
            LogSecurityEvent("Error in IsSuspiciousRequest: " & ex.Message)
            Return False
        End Try
    End Function

    Private Function IsRateLimited(request As HttpRequest) As Boolean
        Try
            Dim clientIP As String = GetClientIP(request)
            Dim cacheKey As String = "RateLimit_" & clientIP
            Dim requestCount As Integer = 0
            
            If HttpContext.Current.Cache(cacheKey) IsNot Nothing Then
                requestCount = CInt(HttpContext.Current.Cache(cacheKey))
            End If
            
            requestCount += 1
            
            ' Allow 60 requests per minute (1 per second average)
            If requestCount > 60 Then
                Return True
            End If
            
            ' Cache for 1 minute
            HttpContext.Current.Cache.Insert(cacheKey, requestCount, Nothing, DateTime.Now.AddMinutes(1), TimeSpan.Zero)
            
            Return False
        Catch ex As Exception
            LogSecurityEvent("Error in IsRateLimited: " & ex.Message)
            Return False
        End Try
    End Function

    Private Function GetClientIP(request As HttpRequest) As String
        Try
            ' Check for IP behind proxy
            Dim ip As String = request.Headers("X-Forwarded-For")
            If String.IsNullOrEmpty(ip) Then
                ip = request.Headers("X-Real-IP")
            End If
            If String.IsNullOrEmpty(ip) Then
                ip = request.UserHostAddress
            End If
            
            ' Take first IP if multiple
            If Not String.IsNullOrEmpty(ip) AndAlso ip.Contains(",") Then
                ip = ip.Split(","c)(0).Trim()
            End If
            
            Return ip
        Catch ex As Exception
            Return request.UserHostAddress
        End Try
    End Function

    Private Function IsProtectedPage(path As String) As Boolean
        ' Define protected pages that require authentication
        Dim protectedPages() As String = {"main.aspx", "admin.aspx", "reports.aspx", "dashboard.aspx"}
        
        For Each page As String In protectedPages
            If path.ToLower().EndsWith(page) Then
                Return True
            End If
        Next
        
        Return False
    End Function

    Private Function IsValidSession(context As HttpContext) As Boolean
        Try
            ' Check if user is authenticated
            If context.Session("authenticated") Is Nothing OrElse context.Session("authenticated") <> True Then
                Return False
            End If
            
            ' Check session timeout
            If context.Session("loginTime") Is Nothing Then
                Return False
            End If
            
            Dim loginTime As DateTime = CType(context.Session("loginTime"), DateTime)
            If DateTime.Now.Subtract(loginTime).TotalMinutes > 30 Then
                context.Session.Clear()
                Return False
            End If
            
            ' Validate session integrity
            If context.Session("sessionToken") Is Nothing OrElse 
               context.Session("userid") Is Nothing OrElse 
               context.Session("username") Is Nothing Then
                context.Session.Clear()
                Return False
            End If
            
            ' Check for session hijacking (IP and User Agent validation)
            If context.Session("ipAddress") IsNot Nothing AndAlso 
               context.Session("ipAddress").ToString() <> context.Request.UserHostAddress Then
                LogSecurityEvent("Potential session hijacking detected - IP mismatch for user: " & context.Session("username").ToString())
                context.Session.Clear()
                Return False
            End If
            
            Return True
        Catch ex As Exception
            LogSecurityEvent("Error in IsValidSession: " & ex.Message)
            Return False
        End Try
    End Function

    Private Sub LogSecurityEvent(message As String)
        Try
            Dim logMessage As String = String.Format("{0}: {1}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), message)
            System.Diagnostics.EventLog.WriteEntry("YTL_Security", logMessage, System.Diagnostics.EventLogEntryType.Warning)
        Catch
            ' Fail silently to prevent information disclosure
        End Try
    End Sub

    Public Sub Dispose() Implements IHttpModule.Dispose
        ' Cleanup if needed
    End Sub

End Class