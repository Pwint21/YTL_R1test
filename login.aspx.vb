Imports System.Data.SqlClient

Namespace AVLS
    Partial Class Login
        Inherits System.Web.UI.Page
        Public errormessage As String = ""
        Public foc As String = "uname"
        Public logoimagepath As String = "images/logo_big.jpg"
        Public backgroundimage As String = "images/lafargeloginpage.jpg"

        Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
            Try



                ImageButton1.Attributes.Add("onclick", "return mysubmit()")

                Session.Abandon()
                'Session.RemoveAll()
                Response.Cookies("userinfo").Expires = DateTime.Now
                Response.Cookies.Remove("userinfo")
                Response.Cookies.Clear()

            Catch ex As Exception
                errormessage = ex.Message.ToString.Replace("'", "\'").Replace(ControlChars.CrLf, "")
            End Try
        End Sub

        Protected Sub ImageButton1_Click(ByVal sender As Object, ByVal e As System.Web.UI.ImageClickEventArgs) Handles ImageButton1.Click
            Try
                Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
                Dim cmd As New SqlCommand("select pwd,role,userid,username,userslist,access,timestamp,usertype,remark,dbip,companyname,customrole from userTBL where upper(username) ='" & UCase(uname.Value) & "' and drcaccess='0'", conn)
                Dim dr As SqlDataReader

                Try

                    conn.Open()
                    dr = cmd.ExecuteReader()

                    If dr.Read() Then

                        If UCase(dr("pwd")) = UCase(password.Value) Then
                            If (Not Request.Cookies("accesslevel") Is Nothing) Then
                                Dim myCookie As HttpCookie
                                myCookie = New HttpCookie("accesslevel")
                                myCookie.Expires = DateTime.Now.AddDays(-1D)
                                Response.Cookies.Add(myCookie)
                            End If

                            Dim access As Byte = dr("access")
                            Response.Cookies("accesslevel")("latedeny") = "false"
                            '############# REMOVE ###################
                            Session("latedeny") = "false"
                            '############# REMOVE ###################

                            Select Case (access)
                                Case 1
                                    If IsDBNull(dr("remark")) Or dr("remark") = Nothing Then
                                        errormessage = "Dear Customer,\n\nYour account is overdue. Kindly remit the total amount due immediately. Sorry for any inconvenience caused."
                                    Else
                                        errormessage = "Dear Customer,\n\n" & dr("remark").ToString.Replace(Environment.NewLine, "\n")
                                    End If
                                    foc = "uname"
                                    Exit Sub
                                Case 2, 3, 4
                                    Dim accessdays() As SByte = {0, -1, 7, 14, 31}
                                    Dim denydatetime As DateTime = DateTime.Parse(dr("timestamp"))
                                    Dim temptime As TimeSpan = DateTime.Now - denydatetime

                                    If temptime.TotalDays <= accessdays(access) Then
                                        Response.Cookies("accesslevel")("latedeny") = "true"
                                        '############# REMOVE ###################
                                        Session("latedeny") = "true"
                                        '############# REMOVE ###################

                                        If IsDBNull(dr("remark")) Or dr("remark") = Nothing Then
                                            Response.Cookies("accesslevel")("remark") = "Dear Customer,\n\nYour account is overdue. Kindly remit the total amount due immediately. Sorry for any inconvenience caused."
                                            '############# REMOVE ###################
                                            Session("remark") = "Dear Customer,\n\nYour account is overdue. Kindly remit the total amount due immediately. Sorry for any inconvenience caused."
                                            '############# REMOVE ###################
                                        Else
                                            Response.Cookies("accesslevel")("remark") = "Dear Customer,\n\n" & dr("remark").ToString.Replace(Environment.NewLine, "\n")
                                            '############# REMOVE ###################vie
                                            Session("remark") = "Dear Customer,\n\n" & dr("remark").ToString.Replace(Environment.NewLine, "\n")
                                            '############# REMOVE ###################
                                        End If
                                    Else
                                        If IsDBNull(dr("remark")) Or dr("remark") = Nothing Then
                                            errormessage = "Dear Customer,\n\nYour account is overdue. Kindly remit the total amount due immediately. Sorry for any inconvenience caused."
                                        Else
                                            errormessage = "Dear Customer,\n\n" & dr("remark").ToString.Replace(Environment.NewLine, "\n")
                                        End If
                                        foc = "uname"
                                        Exit Sub
                                    End If
                            End Select

                            Response.Cookies("accesslevel")("login") = "true"
                            '############# REMOVE ###################
                            Session("login") = "true"
                            '############# REMOVE ###################

                            'If Session("cid") Is Nothing Then
                            '    If Not Request.QueryString("cid") Is Nothing Then
                            '        Session("cid") = Request.QueryString("cid")
                            '    Else
                            '        Session("cid") = 0
                            '    End If
                            'End If
                            If (Not Request.Cookies("userinfo") Is Nothing) Then
                                Dim myCookie As HttpCookie
                                myCookie = New HttpCookie("userinfo")
                                myCookie.Expires = DateTime.Now.AddDays(-1D)
                                Response.Cookies.Add(myCookie)
                            End If
                            '############# REMOVE ###################
                            Session("userid") = dr("userid")
                            Session("username") = dr("username")
                            Session("role") = dr("role")
                            Session("usertype") = dr("usertype")
                            Session("companyname") = dr("companyname")
                            Session("customrole") = dr("customrole")
                            '############# REMOVE ###################



                            Response.Cookies("userinfo")("userid") = dr("userid")
                            Response.Cookies("userinfo")("username") = dr("username")
                            Response.Cookies("userinfo")("role") = dr("role")
                            Response.Cookies("userinfo")("usertype") = dr("usertype")
                            Response.Cookies("userinfo")("companyname") = dr("companyname")
                            Response.Cookies("userinfo")("userslist") = dr("userslist")
                            Response.Cookies("userinfo")("customrole") = dr("customrole")

                            If dr("userid") = "6941" Or dr("userid") = "3342" Or dr("userid") = "439" Or dr("userid") = "742" Or dr("userid") = "1967" Or dr("userid") = "2029" Or dr("userid") = "2041" Or dr("userid") = "2068" Or dr("userid") = "3107" Or dr("userid") = "3352" Or dr("userid") = "8100" Then
                                Response.Cookies("userinfo")("LA") = "Y"
                            Else
                                Response.Cookies("userinfo")("LA") = "N"
                            End If


                            Dim userslist() As String = dr("userslist").ToString().Split(",")
                            Dim usersstring As String = ""

                            For j As Int64 = 0 To userslist.Length - 1
                                usersstring &= "'" & userslist(j) & "',"
                            Next
                            usersstring = usersstring.Remove(usersstring.Length - 1, 1)
                            Response.Cookies("userinfo")("userslist") = usersstring
                            '############# REMOVE ###################
                            Session("userslist") = usersstring
                            '############# REMOVE ###################

                            '******************************************************************************
                            'Store User Log Data into Database
                            Dim role As String = dr("role")
                            Dim username As String = dr("username")
                            Dim applicationversion As String = "Lafarge Beta"
                            Dim logintime As String = Now.ToString("yyyy-MM-dd HH:mm:ss:fff")
                            Response.Cookies("userinfo")("logintime") = logintime
                            '############# REMOVE ###################
                            Session("logintime") = logintime
                            '############# REMOVE ###################
                            Dim hostaddress As String = Request.UserHostAddress
                            Dim browser As String = Request.Browser.Browser & " " & Request.Browser.Version
                            Dim url As String = Request.Url.ToString

                            Try
                                Dim w As Int16 = 0
                                Dim h As Int16 = 0
                                Dim lat As Double = 0
                                Dim lon As Double = 0
                                Dim acc As Integer = 0

                                Try
                                    w = Request.Form("w")
                                    h = Request.Form("h")
                                    lat = Request.Form("lat")
                                    lon = Request.Form("lon")
                                    acc = Request.Form("acc")
                                Catch ex As Exception

                                End Try
                                cmd = New SqlCommand("insert into user_log(userid,logintime,logouttime,hostaddress,browser,applicationversion,url,status,width,height,lat,lon,acc) values('" & dr("userid") & "','" & logintime & "','" & logintime & "','" & hostaddress & "','" & browser & "','" & applicationversion & "','" & url & "',1,'" & w & "','" & h & "','" & lat & "','" & lon & "','" & acc & "')", conn)
                                cmd.ExecuteNonQuery()
                            Catch ex As Exception

                            End Try
                            '******************************************************************************

                            'If Request.Browser.Browser = "IE" Then
                            '    errormessage = "Sorry, we are unable to sign you in using IE at the moment. Please proceed with Google Chrome browser instead. Sorry for any inconvenience caused."
                            'Else
                            Response.Redirect("Main.aspx?n=" & uname.Value)
                            'End If


                        Else
                            errormessage = "Invalid user name or password. Please try again."
                            foc = "password"
                        End If

                    Else
                        errormessage = "Invalid user name or password. Please try again."
                        foc = "uname"
                    End If
                Catch ex As SqlException
                    'If ex.Number = -2 Then
                    errormessage = "Database Server Is not Accessible, please inform YTL IT team to resolve the issue."
                    'End If
                Catch ex As Exception
                    errormessage = "Sorry, server is busy, Please try again later."
                Finally
                    conn.Close()
                End Try
            Catch ex As SqlException
                'If ex.Number = -2 Then
                errormessage = "Database Server Is not Accessible, please inform YTL IT team to resolve the issue."
                ' End If
            Catch ex As Exception
                errormessage = "Sorry, server is busy, Please try again later."
                '  errormessage = ex.Message.ToString.Replace("'", "\'").Replace(ControlChars.CrLf, "")
            End Try

        End Sub

        
    End Class

End Namespace