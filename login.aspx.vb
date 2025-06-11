Imports System.Data.SqlClient
Imports System.Security.Cryptography
Imports System.Text
Imports System.Web.Security

Public Class login
    Inherits System.Web.UI.Page

    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        ' Clear any existing sessions
        Session.Clear()
        Session.Abandon()
    End Sub

    ' SECURITY FIX: Secure login method
    Protected Sub btnLogin_Click(sender As Object, e As EventArgs)
        Try
            Dim username As String = txtUsername.Text.Trim()
            Dim password As String = txtPassword.Text

            ' SECURITY FIX: Input validation
            If String.IsNullOrEmpty(username) Or String.IsNullOrEmpty(password) Then
                lblError.Text = "Please enter both username and password."
                Return
            End If

            ' SECURITY FIX: Validate credentials against database
            If ValidateUser(username, password) Then
                ' SECURITY FIX: Create secure session
                CreateSecureSession(username)
                Response.Redirect("Main.aspx?n=" & Server.UrlEncode(username))
            Else
                lblError.Text = "Invalid username or password."
                LogSecurityEvent("Failed login attempt for username: " & username)
            End If

        Catch ex As Exception
            lblError.Text = "An error occurred during login. Please try again."
            LogSecurityEvent("Login error", ex)
        End Try
    End Sub

    ' SECURITY FIX: Secure user validation with parameterized queries
    Private Function ValidateUser(username As String, password As String) As Boolean
        Try
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As New SqlCommand("SELECT userid, username, password, role, usertype, companyname, userslist, customrole FROM dbo.userTBL WHERE username = @username AND active = 1", conn)
            cmd.Parameters.AddWithValue("@username", username)

            conn.Open()
            Dim dr As SqlDataReader = cmd.ExecuteReader()
            
            If dr.Read() Then
                Dim storedPassword As String = dr("password").ToString()
                
                ' SECURITY FIX: Use proper password hashing (implement your hashing method)
                If VerifyPassword(password, storedPassword) Then
                    ' Store user data in session
                    Session("userid") = dr("userid").ToString()
                    Session("username") = dr("username").ToString()
                    Session("role") = dr("role").ToString()
                    Session("usertype") = dr("usertype").ToString()
                    Session("companyname") = dr("companyname").ToString()
                    Session("userslist") = dr("userslist").ToString()
                    Session("customrole") = dr("customrole").ToString()
                    Session("LA") = "N" ' Default value, set based on your business logic
                    
                    dr.Close()
                    conn.Close()
                    Return True
                End If
            End If
            
            dr.Close()
            conn.Close()
            Return False

        Catch ex As Exception
            LogSecurityEvent("ValidateUser failed for username: " & username, ex)
            Return False
        End Try
    End Function

    ' SECURITY FIX: Create secure session
    Private Sub CreateSecureSession(username As String)
        Try
            ' Clear any existing session
            Session.Clear()
            
            ' Set authentication flag
            Session("authenticated") = True
            Session("loginTime") = DateTime.Now
            
            ' Generate secure session token
            Session("sessionToken") = GenerateSecureToken()
            
            ' Set session timeout (30 minutes)
            Session.Timeout = 30

        Catch ex As Exception
            LogSecurityEvent("CreateSecureSession failed for username: " & username, ex)
        End Try
    End Sub

    ' SECURITY FIX: Generate secure random token
    Private Function GenerateSecureToken() As String
        Try
            Using rng As New RNGCryptoServiceProvider()
                Dim tokenBytes(31) As Byte
                rng.GetBytes(tokenBytes)
                Return Convert.ToBase64String(tokenBytes)
            End Using
        Catch ex As Exception
            LogSecurityEvent("GenerateSecureToken failed", ex)
            Return Guid.NewGuid().ToString()
        End Try
    End Function

    ' SECURITY FIX: Password verification (implement proper hashing)
    Private Function VerifyPassword(plainPassword As String, hashedPassword As String) As Boolean
        Try
            ' TODO: Implement proper password hashing verification
            ' For now, using simple comparison (REPLACE WITH PROPER HASHING)
            ' Use BCrypt, PBKDF2, or similar secure hashing algorithms
            Return plainPassword = hashedPassword
        Catch ex As Exception
            LogSecurityEvent("VerifyPassword failed", ex)
            Return False
        End Try
    End Function

    ' SECURITY FIX: Secure logging
    Private Sub LogSecurityEvent(message As String, Optional ex As Exception = Nothing)
        Try
            Dim logMessage As String = String.Format("{0}: {1} - IP: {2}", 
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), 
                message, 
                Request.UserHostAddress)
            
            If ex IsNot Nothing Then
                logMessage &= " - Error: " & ex.Message
            End If
            
            System.Diagnostics.EventLog.WriteEntry("YTL_Security", logMessage, System.Diagnostics.EventLogEntryType.Warning)
        Catch
            ' Fail silently
        End Try
    End Sub

End Class