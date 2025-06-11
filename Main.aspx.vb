Imports System.Data.SqlClient

Partial Class Main
    Inherits System.Web.UI.Page
    Public IsSpeacialUsers As Boolean = False
    Public username As String = ""
    Public PubUserid As String = ""
    Public mainpage As String = "SmartFleetApk.aspx"
    Public OssReport As Boolean = True
    Public JReport As Boolean = False
    Public role As String = ""
    Public nid As String = "0"
    Public showOss As Boolean = True
    Public viewer As Boolean = False
    Public ytluser As Boolean = False
    Public customRole As String = ""
    Public checkItenery As Boolean = False

    Private Sub Page_Load(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Load, Me.Load
        Try
            If Request.Cookies("userinfo") Is Nothing Then
                Response.Redirect("Login.aspx")
            End If
            Dim uname As String = Request.QueryString("n")
            username = Request.Cookies("userinfo")("username").ToUpper()
            Try
                If uname.ToString.ToUpper() <> username Then
                    Response.Redirect("Login.aspx")
                End If
            Catch ex As Exception

            End Try

            Dim usertype As String = Request.Cookies("userinfo")("usertype")
            Dim userid As String = Request.Cookies("userinfo")("userid")
            PubUserid = userid
            hiduserid.Value = userid
            role = Request.Cookies("userinfo")("role")
            Dim la As String = Request.Cookies("userinfo")("LA")
            If role.StartsWith("Admin") Or la = "Y" Then
                OssReport = False
            End If

            If Request.Cookies("userinfo")("companyname").StartsWith("YTL") Then
                ytluser = True
            Else
                ytluser = False
            End If


            If usertype = "5" Then
                showOss = False
                viewer = True
                OssReport = False
            End If
            If username = "SPYON" Or username = "MARTINYTL" Or role = "Admin" Or username = "SWEEHAR" Or username = "PCWong_BS" Then
                IsSpeacialUsers = True
            End If
            If username = "BINTANG" Or userid = "1912" Or userid = "1934" Or userid = "1618" Or userid = "1933" Or userid = "1944" Then
                JReport = True
            End If

            customrole = Request.cookies("userinfo")("customrole")

            ' '' '' ** For Alerts Calculation
            Dim userslist As String = Request.Cookies("userinfo")("userslist")
            Dim condition As String = ""
            Dim count As Integer = 0
            If role = "User" Then
                condition = " where userid='" & userid & "'"
            ElseIf role = "SuperUser" Or role = "Operator" Then
                condition = " where userid in(" & userslist & ")"
            End If
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As New SqlCommand
            cmd = New SqlCommand("select top 1 id from dbo.alert_notification " & condition & "  order by id  desc", conn)
            Try
                conn.Open()
                Dim dr As SqlDataReader = cmd.ExecuteReader()
                If dr.Read() Then
                    nid = dr("id")
                End If
            Catch ex As Exception
                nid = "0"
            Finally
                conn.Close()
            End Try

            cmd = New SqlCommand("select itenery from dbo.userTBL where userid=" & userid & "", conn)
            Try
                conn.Open()
                Dim dr As SqlDataReader = cmd.ExecuteReader()
                If dr.Read() Then
                    If dr("itenery") = "1" Then
                        checkItenery = True
                    End If
                End If
            Catch ex As Exception
                nid = "0"
            Finally
                conn.Close()
            End Try
        Catch ex As Exception

        End Try
    End Sub

End Class
