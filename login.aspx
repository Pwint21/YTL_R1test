<%@ Page Language="VB" AutoEventWireup="false" EnableEventValidation="false"
    Inherits="YTLWebApplication.AVLS.Login" Codebehind="Login.aspx.vb" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>YTL - AVLS</title>
    <meta name="keywords" content="vehicle tracking, vehicle tracking system, GPS tracking, GPS vehicle tracking, GPS tracking system, automatic vehicle location, tracking system,automatic vehicle locating system, AVLS, GSM GPRS tracking" />
    <meta name="description" content="AVLS is a low cost, features rich versatile system. It utilize both GPS & GSM technologies to track your vehicle at any time and any place via web based." />
    
    <script type="text/javascript">
        function getWindowWidth() { if (window.self && self.innerWidth) { return self.innerWidth; } if (document.documentElement && document.documentElement.clientWidth) { return document.documentElement.clientWidth; } return document.documentElement.offsetWidth; }
        function getWindowHeight() { if (window.self && self.innerHeight) { return self.innerHeight; } if (document.documentElement && document.documentElement.clientHeight) { return document.documentElement.clientHeight; } return document.documentElement.offsetHeight; }
        function mysubmit() { if (document.getElementById("uname").value == "") { alert("Please enter user name"); return false; } else if (document.getElementById("password").value == "") { alert("Please enter password"); return false; } else { document.getElementById("w").value = getWindowWidth(); document.getElementById("h").value = getWindowHeight(); return true; } }
    </script>
    <%  If foc <> "" Then%>
    <script type="text/javascript" language="javascript">
        if (window.parent.frames.length > 0) { window.parent.location = "login.aspx"; }
    </script>
    <%  End If%>
    <style type="text/css">
        body
        {
            font-size: 11px;
            font-family: Verdana, Arial, Helvetica, sans-serif;
        }
        .style2
        {
            font-size: 11px;
            font-family: Verdana, Arial, Helvetica, sans-serif;
            font-weight: bold;
        }
        .style4
        {
            color: #4E6ABD;
        }
        .style5
        {
            color: #666666;
        }
        .style7
        {
            color: #4A6DBE;
        }
        .style9
        {
            font-size: 10px;
            font-family: Verdana, Arial, Helvetica, sans-serif;
            color: #666666;
        }
        .style10
        {
            color: #5270C8;
        }
    </style>
</head>
<body style="margin: 0px;" background="images/blurred-bg-1.jpg">
    <form id="loginform" runat="server" defaultbutton="ImageButton1">
    <center>
        <table width="100%" style="vertical-align: middle;">
           
            <tr align="center">
                <td>
                    <table >  <%--background="images/lafargeloginpage.jpg"--%>
                        <tr align="center">
                            <td>
                                <img src="images/ytl-logo.png" style="width:495px"/>                  
                            </td>
                        </tr>
                        <tr align="center">
                            <td>
                                <table style=" position: relative;">
                                        <tr>
                                            <td>Username</td><td>
                                        <input id="uname" runat="server" type="text" style="width: 150px;" tabindex="1" title="Name of the user" />
                                    </td>
                                        </tr>
                                        <tr>
                                            <td>Password</td><td>
                                        <input id="password" runat="server" type="password" style="width: 150px;" tabindex="2"
                                            title="Password of the user" />
                                    </td>
                                        </tr>
                                    </table>
                                <div style=" position: relative;">
                                        <table>
                                            <tr>
                                                <td style="width: 80px; height: 65px;">
                                                    &nbsp;
                                                </td>
                                                <td>
                                                    <asp:ImageButton ID="ImageButton1" runat="server" ImageUrl="images/glogin_13.jpg"
                                                        Width="69" Height="44" TabIndex="3" />
                                                </td>
                                                <td>
                                                    <input type="reset" title="Cancel" style="border: solid 0px white; background-image: url(images/glogin_14.jpg);
                                                        cursor: pointer; width: 65px; height: 44px;" tabindex="4" value="" onclick="document.loginform.reset()" />
                                                </td>
                                            </tr>
                                        </table>
                                    </div>
                                <%--<div style="width: 495px; height: 394px; left: 0px; top: 0px; text-align: left;">
                                    
                                    
                                    
                                    
                                </div>--%>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr align="center">
                <td>
                    <div class="style2">
                        <span class="style4">24 Hour</span> <span class="style5">Help Line Center :</span>
                        <span class="style7">+60 3625 79472</span> <span class="style5">/ <a href="mailto:info@g1.com.my">
                            info@g1.com.my</a></span></div>
                </td>
            </tr>
            <tr align="center">
                <td>
                    <div class="style2">
                        <span class="style5">Tel :</span> <span class="style7">+60 3625 70509</span> 
                    </div>
                </td>
            </tr>
            <tr align="center">
                <td>
                    <div>
                        <span class="style7">.......................................................................................................................</span>
                    </div>
                </td>
            </tr>
            <tr align="center">
                <td>
                    <p class="style9">
                        <strong>www.g1.com.my</strong><br />
                        Copyright &copy; 2013 <span class="style10">Global Telematics Sdn Bhd</span>. All
                        rights reserved<br />
                        Powered by Integra &reg;<br />
                        Best viewed with Chrome/Firefox at 1366x768 resolution.</p>
                </td>
            </tr>
        </table>
    </center>
    <input type="hidden" name="txtError" value="" />
    <input type="hidden" name="txtSetFocus" value="" />
    <input type="hidden" name="txtStatus" value="False" />&nbsp;<br />
    <input name="w" id="w" type="hidden" value="" />
    <input name="h" id="h" type="hidden" value="" />
    <input name="lat" id="lat" type="hidden" value="" />
    <input name="lon" id="lon" type="hidden" value="" />
    <input name="acc" id="acc" type="hidden" value="" />
    </form>
    
</body>
<script type="text/javascript" language="javascript">
    document.getElementById("uname").focus();
    getLocation();
    function getLocation() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(showPosition);
        }
    }
    function showPosition(position) {
        document.getElementById("lat").value = position.coords.latitude;
        document.getElementById("lon").value = position.coords.longitude;
        document.getElementById("acc").value = position.coords.accuracy;
    }  
</script>
<%  If foc <> "" Then%>
<script type="text/javascript" language="javascript">
    var id = "<%=foc%>"; document.getElementById(id).focus(); document.getElementById(id).select(); 
</script>
<%  End If%>
<%  If errormessage <> "" Then%>
<script type="text/javascript" language="javascript">
    alert('<%= errormessage %>');
</script>
<%  End If%>
</html>
