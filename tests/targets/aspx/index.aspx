<%@ Page Language="C#" ValidateRequest="false" %>
<!DOCTYPE html>
<html><head><title>Corporate Portal (ASPX)</title>
<style>
body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:0 20px}
h1{font-size:1.4em}
form{margin:20px 0;padding:16px;border:1px solid #ccc;border-radius:4px;background:#f9f9f9}
input[type=file]{margin-right:8px}
ul{list-style:none;padding:0} li{padding:4px 0}
</style></head><body>
<h1>Corporate Portal (ASPX)</h1>
<form method="post" enctype="multipart/form-data" action="upload.aspx">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
</form>
<h3>Uploads</h3>
<ul>
<%
    string uploadsDir = Server.MapPath("~/uploads");
    if (System.IO.Directory.Exists(uploadsDir))
    {
        foreach (string f in System.IO.Directory.GetFiles(uploadsDir))
        {
            var info = new System.IO.FileInfo(f);
            Response.Write(string.Format("<li><a href=\"/uploads/{0}\">{0}</a> ({1} bytes)</li>", info.Name, info.Length));
        }
    }
%>
</ul>
</body></html>
