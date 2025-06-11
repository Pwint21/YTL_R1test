Imports System.Web
Imports System.Text.RegularExpressions

Public Class SecurityModule
    Implements IHttpModule

    Public Sub Init(context As HttpApplication) Implements IHttpModule.Init
        AddHandler context.BeginRequest, AddressOf OnBeginRequest
        AddHandler context.PreExecuteRequestHandler, AddressOf OnPreExecuteRequestHandler
    End Sub

    Private Sub OnBeginRequest(sender As Object, e As EventArgs)
        Dim context As HttpContext = HttpContext.Current
        
        ' SECURITY FIX: Block suspicious requests
        If IsSuspiciousRequest(context.Request) Then
            context.Response.StatusCode = 400
            context.Response.End()
            Return
        End If
        
        ' SECURITY FIX: Rate limiting (basic implementation)
        If IsRateLimited(context.Request) Then
            context.Response.StatusCode = 429
            context.Response.End()
            Return
        End If
    End Sub

    Private Sub OnPreExecuteRequestHandler(sender As Object, e As EventArgs)
        Dim context As HttpContext = HttpContext.Current
        
        ' SECURITY FIX: Validate session for protected pages
        If IsProtectedPage(context.Request.Url.AbsolutePath) Then
            If Not IsValidSession(context) Then
                context.Response.Redirect("login.aspx")
                Return
            End If
        End If
    End Sub

    Private Function IsSuspiciousRequest(request As HttpRequest) As Boolean
        Try
            ' Check for SQL injection patterns
            Dim sqlPatterns() As String = {
                "(\%27)|(\')|(\-\-)|(\%23)|(#)",
                "((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                "\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                "((\%27)|(\'))union"
            }
            
            Dim queryString As String = request.QueryString.ToString().ToLower()
            Dim formData As String = ""
            
            ' Check form data if POST request
            If request.HttpMethod = "POST" AndAlso request.Form IsNot Nothing Then
                For Each key As String In request.Form.AllKeys
                    formData &= request.Form(key) & " "
                Next
                formData = formData.ToLower()
            End If
            
            For Each pattern As String In sqlPatterns
                If Regex.IsMatch(queryString, pattern, RegexOptions.IgnoreCase) OrElse
                   Regex.IsMatch(formData, pattern, RegexOptions.IgnoreCase) Then
                    LogSecurityEvent("Suspicious SQL injection attempt detected from IP: " & request.UserHostAddress)
                    Return True
                End If
            Next
            
            ' Check for XSS patterns
            Dim xssPatterns() As String = {
                "<script[^>]*>.*?</script>",
                "javascript:",
                "vbscript:",
                "onload=",
                "onerror=",
                "onclick="
            }
            
            For Each pattern As String In xssPatterns
                If Regex.IsMatch(queryString, pattern, RegexOptions.IgnoreCase) OrElse
                   Regex.IsMatch(formData, pattern, RegexOptions.IgnoreCase) Then
                    LogSecurityEvent("Suspicious XSS attempt detected from IP: " & request.UserHostAddress)
                    Return True
                End If
            Next
            
            Return False
        Catch ex As Exception
            LogSecurityEvent("Error in IsSuspiciousRequest: " & ex.Message)
            Return False
        End Try
    End Function

    Private Function IsRateLimited(request As HttpRequest) As Boolean
        Try
            ' Basic rate limiting implementation
            Dim clientIP As String = request.UserHostAddress
            Dim cacheKey As String = "RateLimit_" & clientIP
            Dim requestCount As Integer = 0
            
            If HttpContext.Current.Cache(cacheKey) IsNot Nothing Then
                requestCount = CInt(HttpContext.Current.Cache(cacheKey))
            End If
            
            requestCount += 1
            
            ' Allow 100 requests per minute
            If requestCount > 100 Then
                LogSecurityEvent("Rate limit exceeded for IP: " & clientIP)
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

    Private Function IsProtectedPage(path As String) As Boolean
        ' Define protected pages that require authentication
        Dim protectedPages() As String = {"main.aspx", "admin.aspx", "reports.aspx"}
        
        For Each page As String In protectedPages
            If path.ToLower().EndsWith(page) Then
                Return True
            End If
        Next
        
        Return False
    End Function

    Private Function IsValidSession(context As HttpContext) As Boolean
        Try
            If context.Session("authenticated") Is Nothing OrElse context.Session("authenticated") <> True Then
                Return False
            End If
            
            If context.Session("loginTime") Is Nothing Then
                Return False
            End If
            
            Dim loginTime As DateTime = CType(context.Session("loginTime"), DateTime)
            If DateTime.Now.Subtract(loginTime).TotalMinutes > 30 Then
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
            ' Fail silently
        End Try
    End Sub

    Public Sub Dispose() Implements IHttpModule.Dispose
        ' Cleanup if needed
    End Sub

End Class